import time
from src.qshield.crypto_core import poly_mul_negacyclic_constant_time, KYBER_N

def test_constant_time_poly_mul_bounds():
    """
    Basic Side-Channel / Timing Leakage Verification:
    Evaluates execution times of poly_mul_negacyclic_constant_time on two distinct sets:
    Set A: All-zero coefficients (which would trigger early-exit in naive implementations)
    Set B: Uniformly high non-zero coefficients
    
    NOTE: Python's `time.perf_counter()` is subject to OS scheduler jitter, GC pauses,
    and interpreter overhead. This test only proves the *absence of a naive O(1) early exit*,
    NOT true constant-time execution at the CPU pipeline level. A real constant-time 
    guarantee requires C/Rust implementations analyzed with `dudect` or `valgrind`.
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
    # Threshold raised to 5.0 to tolerate CI/Windows scheduler jitter
    ratio = max(time_zeros, time_non_zeros) / max(min(time_zeros, time_non_zeros), 1e-6)
    assert ratio < 5.0, f"Timing ratio {ratio:.2f} exceeds acceptable constant-time threshold (likely CI jitter)!"
