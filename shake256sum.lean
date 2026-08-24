import Crypto.CLI

def main (args : List String) : IO UInt32 :=
  Crypto.CLI.runShakeSumMain Crypto.Hash.XofAlgorithm.shake256 "shake256sum" args
