module Rivum.CWE where

import Data.List (elem)
import Rivum.CVSS

type Id = Int

-- We only need a mapping from CWE IDs to impacts,
-- partial (P) or complete (C), hence a CVSS Base-update function

-- TODO fill with actual values
partialConf :: [Id]
partialConf =
    [ 100
    , 101
    ]

completeConf :: [Id]
completeConf =
    [
    ]

partialInteg :: [Id]
partialInteg =
    [
    ]

completeInteg :: [Id]
completeInteg =
    [
    ]

partialAvail :: [Id]
partialAvail =
    [
    ]

completeAvail :: [Id]
completeAvail =
    [
    ]

cweImpact :: Id -> Base -> Base
cweImpact i = (confImpact i) . (integImpact i) . (availImpact i)

confImpact :: Id -> Base -> Base
confImpact i b
  | i `elem` completeConf = b { c = ImpC }
  | i `elem` partialConf  = b { c = ImpP }
  | otherwise             = b

integImpact :: Id -> Base -> Base
integImpact i b
  | i `elem` completeInteg = b { i = ImpC }
  | i `elem` partialInteg  = b { i = ImpP }
  | otherwise              = b

availImpact :: Id -> Base -> Base
availImpact i b
  | i `elem` completeAvail = b { a = ImpC }
  | i `elem` partialAvail  = b { a = ImpP }
  | otherwise              = b
