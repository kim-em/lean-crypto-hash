import CryptoValidation.OfficialVectors

def main : IO UInt32 := do
  if ← CryptoValidation.OfficialVectors.run then return 0 else return 1
