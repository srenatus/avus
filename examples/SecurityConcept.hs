module Rivum.SecurityConcept
  ( Requirements(..)
  , SecurityConcept
  , exampleConcept
  ) where

import Rivum.CodeModel

data Requirements = ConfidentialityR
                  | IntegrityR
		  | AvailabilityR
		    deriving (Eq, Show)

type SecurityConcept = Domain -> [Requirements]

exampleConcept :: SecurityConcept
exampleConcept Userland = [ConfidentialityR]
exampleConcept Misc = [IntegrityR]
exampleConcept Kernel = [AvailabilityR]
