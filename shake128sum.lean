module

import Crypto.CLI

public section

def main (args : List String) : IO UInt32 :=
  Crypto.CLI.runShakeSumMain Crypto.Hash.XofAlgorithm.shake128 "shake128sum" args
