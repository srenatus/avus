-- | Utility function module
module Avus.Utils (returnIO) where

-- | IO-ify a pure CVSS score update function
returnIO :: (a -> b -> c) -> a -> b -> IO c
returnIO f = (return .) . f
