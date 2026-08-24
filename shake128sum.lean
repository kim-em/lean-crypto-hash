import Crypto.CLI

def main (args : List String) : IO UInt32 :=
  Crypto.CLI.runShakeSumMain Crypto.Hash.XofAlgorithm.shake128 "shake128sum" args
