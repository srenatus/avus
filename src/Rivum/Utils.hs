module Rivum.Utils (returnIO) where

returnIO :: (a -> b -> c) -> a -> b -> IO c
returnIO f = (return .) . f
