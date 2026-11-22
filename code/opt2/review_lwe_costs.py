"""Verify the published default LWE cost records with Python's standard library."""
import csv
import io
import json
import math
import re
import sys
from decimal import Decimal, localcontext
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

import spiral_kem_toy_v031_opt2 as opt2


ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / "archives/research/Spiral_v031_n256_eta1_attack_costs.zip"
SIX = ROOT / "archives/research/Spiral_KEM_six_candidates_results.zip"
FRESH = ROOT / "results/lattice_cost_review/sage-replay.zip"
UPSTREAM = "e4333d9bf9ef42fd8a29651b0c559fba7ce0d834"
PROFILES = {"spiral_cbd1": (1, "A_k2_eta1"), "kyber512_pk_reference_cbd3": (3, "C_k2_eta3")}
MODELS = {"matzov_classical": ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid", "bkw", "arora_gb"),
          "core_svp_classical": ("usvp", "dual_hybrid"), "core_svp_quantum_primal": ("usvp",)}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def archive_root(z):
    root = z.namelist()[0].split("/")[0] + "/"
    listed = {}
    for line in z.read(root + "SHA256SUMS").decode().splitlines():
        digest, name = line.split(None, 1)
        require(sha256(z.read(root + name)).hexdigest() == digest, name)
        listed[root + name] = digest
    require(set(listed) | {root + "SHA256SUMS"} == set(z.namelist()), "incomplete manifest")
    return root


def code_mapping():
    kem = opt2.SpiralKEM()
    n, k, q = kem.p.n, kem.p.k, kem.p.q
    require((n, k, q, kem.p.eta, kem.p.key_bytes) == (256, 2, 3329, 1, 32), "OPT2 defaults changed")
    rho, sigma, fallback, msg = bytes(range(32)), b"S" * 32, b"Z" * 32, bytes(range(32))
    with patch.object(opt2.secrets, "token_bytes", side_effect=[rho, sigma, fallback, msg]):
        pk, sk = kem.keygen()
        ct, _ = kem.encapsulate(pk)
    matrix = kem._base_matrix(rho)
    e = kem._small_vector(sigma, b"key/e")
    coins = kem._coin_seed(pk, msg)
    r = kem._small_vector(coins, b"enc/r")
    e1 = kem._small_vector(coins, b"enc/e1")
    e2 = kem._small_poly(coins, b"enc/e2")

    def dot(row, x, addend):
        result = []
        for i in range(n):
            total = addend[i]
            for poly, secret in zip(row, x, strict=True):
                total += sum((poly[i-j] if j <= i else -poly[n+i-j]) * secret[j] for j in range(n))
            result.append(total % q)
        return tuple(result)

    require(tuple(dot(row, sk.s, err) for row, err in zip(matrix, e)) == pk.t, "public key map")
    require(tuple(dot(col, r, err) for col, err in zip(zip(*matrix), e1)) == ct.u, "ciphertext u map")
    encoded = [1664 * (msg[i//8] >> (i % 8) & 1) + e2[i] for i in range(n)]
    require(dot(pk.t, r, encoded) == ct.v, "ciphertext v map")
    return {"ring_degree": n, "module_rank": k, "q": q, "lwe_n": n*k, "lwe_m": n*k,
            "fixture_coefficients_checked": {"t": n*k, "u": n*k, "v": n},
            "current_opt2_sha256": sha256(Path(opt2.__file__).read_bytes()).hexdigest(),
            "legacy_pk_sha256": sha256(kem.serialize_public_key(pk)).hexdigest(),
            "legacy_ct_sha256": sha256(kem.serialize_ciphertext(ct)).hexdigest()}


def primal_gsa(eta):
    """Enumerate GSA dimensions for the equal-noise, inhomogeneous uSVP embedding."""
    n, q, sigma = 512, 3329, math.sqrt(eta / 2)
    a, b = 0.29613500308205365, 20.387885985467914
    overhead = 1 / (1 - 2**(-a))
    best = {}
    for beta in range(40, 2*n + 1):
        ld = math.log(1.01295) if beta == 40 else (
            math.log(beta/(2*math.pi*math.e)) + math.log(math.pi*beta)/beta) / (2*(beta-1))
        for d in range(max(n, min(beta+1, 2*n)), 2*n + 1):
            rhs = (2*beta-d-1)*ld + (math.log(sigma) + (d-n-1)*math.log(q))/d
            if math.log(sigma) + math.log(beta)/2 > rhs:
                continue
            effective = beta - beta*math.log(4/3)/math.log(beta/(2*math.pi*math.e))
            gates = d**3 + overhead**2 * max(d-beta, 1) * 2**(a*effective+b)
            prices = {"matzov_classical": math.log2(gates),
                      "core_svp_classical": 0.292*beta, "core_svp_quantum_primal": 0.265*beta}
            for model, price in prices.items():
                if model not in best or price < best[model]["log2_rop"]:
                    best[model] = {"log2_rop": price, "beta": beta, "d": d}
            # All three prices are nondecreasing in d at fixed beta.
            break
    return best


def log_cost(raw):
    if raw == "+Infinity":
        return "Infinity"
    with localcontext() as ctx:
        ctx.prec = 60
        # Two archived CBD1 dual-hybrid totals contain a Sage exponential.
        total = Decimal(0)
        for term in raw.split(" + "):
            match = re.fullmatch(r"([\d.eE+-]+)(?:\*e\^\((-?\d+)\))?", term)
            require(match, f"Unknown raw cost expression: {raw}")
            value = Decimal(match[1])
            if match[2] is not None:
                value *= Decimal(match[2]).exp()
            total += value
        return float(total.ln() / Decimal(2).ln())


def same_log(x, y, tolerance):
    if x == "Infinity" or y == "Infinity":
        return x == y
    return abs(float(x) - float(y)) <= tolerance


def load_record(z, prefix, name):
    raw = json.loads(z.read(prefix + name + ".json"))
    lines = z.read(prefix + name + ".txt").decode().splitlines()
    metadata = json.loads(next(x.removeprefix("METADATA ") for x in lines if x.startswith("METADATA ")))
    command = json.loads(next(x.removeprefix("COMMAND ") for x in lines if x.startswith("COMMAND ")))
    fields_line = next(x for x in lines if x.startswith("RAW_FIELDS "))
    expr = re.search(r"'rop': ([^,}]+)", fields_line).group(1)
    require(expr == raw["raw_fields"]["rop"] and "RAW_COST_REPR " + raw["raw_cost_repr"] in lines, name)
    for key, value in metadata.items():
        require(raw[key] == value, (name, key))
    for key in ("profile", "model", "attack"):
        require(command[command.index("--" + key) + 1] == raw[key], (name, key))
    require(name == "__".join(raw[s] for s in ("profile", "model", "attack")), name)
    return raw, log_cost(expr)


def comparison():
    rows = []
    opt2_map = code_mapping()
    primal = {p: primal_gsa(eta) for p, (eta, _) in PROFILES.items()}
    with ZipFile(OLD) as old, ZipFile(SIX) as six, ZipFile(FRESH) as fresh:
        r, s = archive_root(old), archive_root(six)
        pinned_source = sha256(old.read(r + "source/spiral_kem_toy_v031.py")).hexdigest()
        manifest = json.loads(old.read(r + "results/run-manifest.json"))
        columns = list(csv.DictReader(io.StringIO(old.read(r + "results/summary.csv").decode())))
        expected = {(p, m, a) for p in PROFILES for m in MODELS for a in MODELS[m]}
        require(expected == {tuple(x) for x in manifest["jobs"]} and len(columns) == len(expected), "job set")
        for c in columns:
            p, model, attack = c["profile"], c["model"], c["attack"]
            expected.remove((p, model, attack))
            eta, candidate = PROFILES[p]
            name = "__".join((p, model, attack))
            historical, from_text = load_record(old, r + "results/raw/", name)
            replicate, other_text = load_record(six, s + "results/attacks/raw/", "__".join((candidate, model, attack)))
            rerun, fresh_text = load_record(fresh, "raw/", name)
            issues = []
            for raw in (historical, replicate, rerun):
                distribution = f"CenteredBinomial({eta})"
                inputs = (raw["lwe_n"], raw["lwe_m"], raw["q"], raw["secret_distribution"], raw["error_distribution"])
                if inputs != (512, 512, 3329, distribution, distribution) or raw["estimator_commit"] != UPSTREAM:
                    issues.append("model input or commit")
                expected_price = ("MATZOV", {"nn": "list_decoding-classical"}) if model == "matzov_classical" else (
                    "ADPS16", {"mode": "quantum" if model == "core_svp_quantum_primal" else "classical"})
                if (raw["reduction_model"], raw["reduction_model_state"]) != expected_price or raw["shape_model"] != "GSA":
                    issues.append("reduction or configured shape model")
                if raw["status"] != "ok" or raw["sage_version"] != "10.8" or raw["source_sha256"] != pinned_source:
                    issues.append("job status, Sage version or historical KEM source hash")
            reported = historical["log2_metrics"]["rop"]
            published = c["log2_rop"]
            if c["status"] != "ok" or not same_log(reported, published, 5.01e-7):
                issues.append("published CSV")
            for tag, measured in (("old text", from_text), ("second text", other_text), ("fresh text", fresh_text)):
                if not same_log(measured, reported, 5e-7):
                    issues.append(tag)
            for tag, raw in (("second archive", replicate), ("fresh run", rerun)):
                if raw["log2_metrics"] != historical["log2_metrics"]:
                    issues.append(tag + " metrics")
                for field in ("beta", "d", "m", "N", "mem", "zeta", "t", "p", "beta_"):
                    if raw["raw_fields"].get(field) != historical["raw_fields"].get(field):
                        issues.append(tag + " " + field)
            fields = historical["raw_fields"]
            if attack == "usvp":
                independent = primal[p][model]
                if ((int(fields["beta"]), int(fields["d"])) != (independent["beta"], independent["d"])
                        or not same_log(reported, independent["log2_rop"], 1e-8)):
                    issues.append("independent GSA sweep")
            rows.append(dict(profile=p, model=model, method=attack, archived_csv_log2_rop=published,
                             raw_text_log2_rop=from_text, fresh_log2_rop=rerun["log2_metrics"]["rop"],
                             second_archive_log2_rop=replicate["log2_metrics"]["rop"],
                             log2_mem=historical["log2_metrics"].get("mem"),
                             log2_N=historical["log2_metrics"].get("N"), returned_m=fields.get("m"),
                             raw_name=name, discrepancies=issues))
    return {"scope": "single-public-instance generic LWE costs", "estimator_commit": UPSTREAM,
            "source_mapping": opt2_map, "independent_primal_gsa": primal,
            "input_archives_sha256": {p.name: sha256(p.read_bytes()).hexdigest() for p in (OLD, SIX, FRESH)},
            "rows": rows}


if __name__ == "__main__":
    report = comparison()
    print(json.dumps(report, indent=2, allow_nan=False))
    sys.exit(int(any(row["discrepancies"] for row in report["rows"])))
