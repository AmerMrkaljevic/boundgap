// Synthetic example shaped after the real libsrt bug that motivated boundgap
// (handshake.cpp validates a minimum MSS, core.cpp subtracts a larger
// constant from it). Nothing here is a real vulnerability in any real
// project -- it exists purely so you can see boundgap flag something
// immediately after cloning, without needing a real codebase on hand.
//
// Run:
//   python3 boundgap.py examples/
//
// Expected output: one candidate gap on `mss`, same-file, gap 12.

bool validateHandshake(int mss) {
    if (mss < 32) {          // validator: guarantees mss >= 32
        return false;
    }
    return true;
}

void computePayloadSize(int mss) {
    int maxPayload = mss - 44;   // consumer: actually needs mss >= 44
    (void)maxPayload;
}
