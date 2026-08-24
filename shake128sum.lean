import Crypto.CLI

def main (args : List String) : IO UInt32 :=
  Crypto.CLI.runShakeSumMain HashAlgorithm.shake128 "shake128sum" args
