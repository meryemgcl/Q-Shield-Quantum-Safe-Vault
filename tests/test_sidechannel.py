import time
from crypto_core import poly_mul_negacyclic_constant_time, KYBER_N

def test_constant_time_poly_mul_bounds():
    """
    Side-Channel / Timing Leakage Verification (dudect simulation):
    Evaluates execution times of poly_mul_negacyclic_constant_time on two distinct sets:
    Set A: All-zero coefficients (which would trigger early-exit in naive implementations)
    Set B: Uniformly high non-zero coefficients
    Verifies that no fast-path branch causes severe timing skew.
    """
    zero_poly = [0] * KYBER_N
    rand_poly = [1500] * KYBER_N

    # Warmup
    for _ in range(5):
        poly_mul_negacyclic_constant_time(zero_poly, zero_poly)

    # Measure Set A (Zeros)
    t0 = time.perf_counter()
    for _ in range(10):
        poly_mul_negacyclic_constant_time(zero_poly, zero_poly)
    time_zeros = time.perf_counter() - t0

    # Measure Set B (Non-zeros)
    t0 = time.perf_counter()
    for _ in range(10):
        poly_mul_negacyclic_constant_time(rand_poly, rand_poly)
    time_non_zeros = time.perf_counter() - t0

    # Ratio should remain bounded within reasonable execution window (no 10x early exit drop)
    ratio = max(time_zeros, time_non_zeros) / max(min(time_zeros, time_non_zeros), 1e-6)
    assert ratio < 3.0, f"Timing ratio {ratio:.2f} exceeds acceptable constant-time threshold!"
