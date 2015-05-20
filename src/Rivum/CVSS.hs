{-# LANGUAGE NamedFieldPuns #-}
module Rivum.CVSS where

import Data.Decimal (Decimal, roundTo)
type Score = Decimal

-- Base
data Av = AvL | AvA | AvN deriving (Eq, Show)
data Ac = AcH | AcM | AcL deriving (Eq, Show)
data Au = AuM | AuS | AuN deriving (Eq, Show)
data Imp = ImpN | ImpP | ImpC deriving (Eq, Show)

fromAv :: Av -> Decimal
fromAv AvL = 0.395
fromAv AvA = 0.646
fromAv AvN = 1.0

fromAc :: Ac -> Decimal
fromAc AcH = 0.35
fromAc AcM = 0.61
fromAc AcL = 0.71

fromAu :: Au -> Decimal
fromAu AuM = 0.45
fromAu AuS = 0.56
fromAu AuN = 0.704

fromImp :: Imp -> Decimal
fromImp ImpN = 0.0
fromImp ImpP = 0.275
fromImp ImpC = 0.660

data Base = Base
    { av :: Av
    , ac :: Ac
    , au :: Au
    , c  :: Imp
    , i  :: Imp
    , a  :: Imp
    } deriving (Eq, Show)

defaultBase = Base
    { av = AvL
    , ac = AcH
    , au = AuM
    , c  = ImpN
    , i  = ImpN
    , a  = ImpN
    }

baseByImp :: Decimal -> Base -> Score
baseByImp imp (Base { av, ac, au }) = roundTo 1 $ ( 0.6 * imp + 0.4 * exploitability - 1.5 ) * (f imp)
  where
    exploitability = 20 * accessVector * accessComplexity * authentication
    accessVector     = fromAv av
    accessComplexity = fromAc ac
    authentication   = fromAu au
    f x = if x == 0.0 then 0.0 else 1.176

base :: Base -> Score
base b@(Base { c, i, a }) = baseByImp imp b
  where
    imp         = impact confImpact integImpact availImpact
    confImpact  = fromImp c
    integImpact = fromImp i
    availImpact = fromImp a

impact :: Decimal -> Decimal -> Decimal -> Decimal
impact ci ii ai = 10.41 * (1 - (1 - ci) * (1 - ii) * (1 - ai))

-- Temp
data E = END | EU | EPOC | EF | EH deriving (Eq, Show)
data Rl = RlND | RlOF | RlTF | RlW | RlU deriving (Eq, Show)
data Rc = RcND | RcUC | RcUR | RcC deriving (Eq, Show)

fromE :: E -> Decimal
fromE END  = 1.0
fromE EU   = 0.85
fromE EPOC = 0.9
fromE EF   = 0.95
fromE EH   = 1.0

fromRl :: Rl -> Decimal
fromRl RlND = 1.0
fromRl RlOF = 0.87
fromRl RlTF = 0.9
fromRl RlW  = 0.95
fromRl RlU  = 1.0

fromRc :: Rc -> Decimal
fromRc RcND = 1.0
fromRc RcUC   = 0.9
fromRc RcUR = 0.95
fromRc RcC  = 1.0

data Temp = Temp
    { e  :: E
    , rl :: Rl
    , rc :: Rc
    }

defaultTemp = Temp
    { e  = END
    , rl = RlND
    , rc = RcND
    }

tempByBase :: Score -> Temp -> Score
tempByBase baseScore (Temp {e, rl, rc}) = roundTo 1 $ baseScore * exploitability * remediationLevel * reportConfidence
  where
    exploitability = fromE e
    remediationLevel = fromRl rl
    reportConfidence = fromRc rc

temp :: Base -> Temp -> Score
temp b = tempByBase baseScore
  where
    baseScore = base b

-- Env
data Cdp = CdpND | CdpN | CdpL | CdpLM | CdpMH | CdpH deriving (Eq, Show)
data Td  = TdND | TdN | TdL | TdM | TdH deriving (Eq, Show)
data Req = ReqND | ReqL | ReqM | ReqH deriving (Eq, Show)

fromCdp :: Cdp -> Decimal
fromCdp CdpND = 0.0
fromCdp CdpN  = 0.0
fromCdp CdpL  = 0.1
fromCdp CdpLM = 0.3
fromCdp CdpMH = 0.4
fromCdp CdpH  = 0.5

fromTd :: Td -> Decimal
fromTd TdND = 1.0
fromTd TdL  = 0.25
fromTd TdM  = 0.75
fromTd TdH  = 1.0

fromReq :: Req -> Decimal
fromReq ReqND = 1.0
fromReq ReqL  = 0.5
fromReq ReqM  = 1.0
fromReq ReqH  = 1.51

type EnvScore = Decimal

data Env = Env
    { cdp :: Cdp
    , td  :: Td
    , cr  :: Req
    , ir  :: Req
    , ar  :: Req
    } deriving (Eq, Show)

defaultEnv = Env
    { cdp = CdpND
    , td  = TdND
    , cr  = ReqND
    , ir  = ReqND
    , ar  = ReqND
    }

env :: Base -> Temp -> Env -> Score
env b@(Base { c, i, a}) t  (Env { cdp, td, cr, ir, ar }) = roundTo 1 $ (adjustedTemporal + (10 - adjustedTemporal) * collateralDamagePotential) * targetDistribution
  where
    adjustedTemporal = tempByBase (baseByImp adjustedImpact b) t
    adjustedImpact = minimum [10.0, impact (confImpact*confReq) (integImpact*integReq) (availImpact*availReq)]
    collateralDamagePotential = fromCdp cdp
    targetDistribution = fromTd td
    confImpact  = fromImp c
    integImpact = fromImp i
    availImpact = fromImp a
    confReq  = fromReq cr
    integReq = fromReq ir
    availReq = fromReq ar

-- NVD classification
data Severity = Low | Medium | High
fromScore :: Score -> Severity
fromScore s
    | s <= 3.9  = Low
    | s <= 6.9  = Medium
    | otherwise = High

fromSeverity :: Severity -> String
fromSeverity Low = "low"
fromSeverity Medium = "medium"
fromSeverity High = "high"
