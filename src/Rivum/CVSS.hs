-- | CVSS functions
{-# LANGUAGE NamedFieldPuns #-}
module Rivum.CVSS (
  -- * Basic types
    Score
  , Severity
  -- * Base scoring
  , Base(..)
  , Av(..)
  , Ac(..)
  , Au(..)
  , Imp(..)
  , base
  , defaultBase
  -- * Temp scoring
  , Temp(..)
  , E(..)
  , Rl(..)
  , Rc(..)
  , temp
  , defaultTemp
  -- * Env scoring
  , Cdp(..)
  , Td(..)
  , Req(..)
  , Env(..)
  , env
  , defaultEnv
  -- * Helper functions
  , fromScore
  , fromSeverity
  ) where

import Data.Decimal (Decimal, roundTo)

-- | Score data type
--
-- According to the documentation, the resulting scores are all rounded to one
-- decimal.
type Score = Decimal

-- | Access vector
data Av = AvL  -- ^ requires local access
        | AvA  -- ^ adjacent network access
        | AvN  -- ^ network accessible
          deriving (Eq, Show)

-- | Access complexity
data Ac = AcH  -- ^ high
        | AcM  -- ^ medium
        | AcL  -- ^ low
          deriving (Eq, Show)

-- | Authentication
data Au = AuM  -- ^ requires multiple instances of authentication
        | AuS  -- ^ requires single instance of authentication
        | AuN  -- ^ requires no authentication
          deriving (Eq, Show)

-- | Impact
data Imp = ImpN  -- ^ none
         | ImpP  -- ^ partial
         | ImpC  -- ^ complete
           deriving (Eq, Show)

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

-- | Base score configuration
data Base = Base
    { av :: Av   -- ^ access vector
    , ac :: Ac   -- ^ access complexity
    , au :: Au   -- ^ authentication
    , c  :: Imp  -- ^ confidentiality impact
    , i  :: Imp  -- ^ integrity impact
    , a  :: Imp  -- ^ availability impact
    } deriving (Eq, Show)

-- | Default base score configuration
defaultBase = Base
    { av = AvL
    , ac = AcH
    , au = AuM
    , c  = ImpN
    , i  = ImpN
    , a  = ImpN
    }

-- | Calculate base score given a certain impact
baseByImp :: Decimal -> Base -> Score
baseByImp imp (Base { av, ac, au }) = roundTo 1 $ ( 0.6 * imp + 0.4 * exploitability - 1.5 ) * (f imp)
  where
    exploitability = 20 * accessVector * accessComplexity * authentication
    accessVector     = fromAv av
    accessComplexity = fromAc ac
    authentication   = fromAu au
    f x = if x == 0.0 then 0.0 else 1.176

-- | Base scoring function
--
-- >>> base defaultBase
-- 0.0
base :: Base -> Score
base b@(Base { c, i, a }) = baseByImp imp b
  where
    imp         = impact confImpact integImpact availImpact
    confImpact  = fromImp c
    integImpact = fromImp i
    availImpact = fromImp a

-- | Calculate combined impact given impacts on confidentiality, integrity, and
--   availability
impact :: Decimal -> Decimal -> Decimal -> Decimal
impact ci ii ai = 10.41 * (1 - (1 - ci) * (1 - ii) * (1 - ai))

-- | Exploitability
data E = END   -- ^ not defined
       | EU    -- ^ unproven
       | EPOC  -- ^ proof-of-concept
       | EF    -- ^ functional
       | EH    -- ^ high
         deriving (Eq, Show)

-- | Remediation level
data Rl = RlND  -- ^ not defined
        | RlOF  -- ^ official-fix
        | RlTF  -- ^ temporary-fix
        | RlW   -- ^ workaround
        | RlU   -- ^ unavailable
          deriving (Eq, Show)

-- | Report confidence
data Rc = RcND  -- ^ not defined
        | RcUC  -- ^ unconfirmed
        | RcUR  -- ^ uncorroborated
        | RcC   -- ^ confirmed
          deriving (Eq, Show)

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

-- | Temp score configuration
data Temp = Temp
    { e  :: E
    , rl :: Rl
    , rc :: Rc
    } deriving (Eq, Show)

-- | Default temp configuration: not defined
defaultTemp = Temp
    { e  = END
    , rl = RlND
    , rc = RcND
    }

-- | Temp score given a base score (not base config)
tempByBase :: Score -> Temp -> Score
tempByBase baseScore (Temp {e, rl, rc}) = roundTo 1 $ baseScore * exploitability * remediationLevel * reportConfidence
  where
    exploitability = fromE e
    remediationLevel = fromRl rl
    reportConfidence = fromRc rc

-- | Calculate temp score given base config and temp config
--
-- >>> temp defaultBase defaultTemp
-- 0.0
temp :: Base -> Temp -> Score
temp b = tempByBase baseScore
  where
    baseScore = base b

-- | Collateral damage potential
data Cdp = CdpND  -- ^ not defined
         | CdpN   -- ^ none
         | CdpL   -- ^ low
         | CdpLM  -- ^ low-medium
         | CdpMH  -- ^ medium-high
         | CdpH   -- ^ high
           deriving (Eq, Show)

-- | Target distribution
data Td = TdND  -- ^ not defined
        | TdN   -- ^ none
        | TdL   -- ^ low
        | TdM   -- ^ medium
        | TdH   -- ^ high
          deriving (Eq, Show)

-- | Requirement (of confidentiality, integrity, or availability)
data Req = ReqND  -- ^ not defined
         | ReqL   -- ^ low
         | ReqM   -- ^ medium
         | ReqH   -- ^ high
           deriving (Eq, Show)

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

-- | Env score configuration
data Env = Env
    { cdp :: Cdp
    , td  :: Td
    , cr  :: Req  -- ^ confidentiality requirement
    , ir  :: Req  -- ^ integrity requirement
    , ar  :: Req  -- ^ availability requirement
    } deriving (Eq, Show)

-- | Default Env configuration: not defined
defaultEnv = Env
    { cdp = CdpND
    , td  = TdND
    , cr  = ReqND
    , ir  = ReqND
    , ar  = ReqND
    }

-- | Calculate env score given base, temp, and env config
--
-- >>> env defaultBase defaultTemp defaultEnv
-- 0.0
env :: Base -> Temp -> Env -> Score
env b@(Base { c, i, a}) t  (Env { cdp, td, cr, ir, ar }) = roundTo 1 $ (adjustedTemporal + (10 - adjustedTemporal) * collateralDamagePotential) * targetDistribution
  where
    adjustedTemporal          = tempByBase (baseByImp adjustedImpact b) t
    adjustedImpact            = minimum [10.0, impact (confImpact*confReq) (integImpact*integReq) (availImpact*availReq)]
    collateralDamagePotential = fromCdp cdp
    targetDistribution        = fromTd td
    confImpact  = fromImp c
    integImpact = fromImp i
    availImpact = fromImp a
    confReq  = fromReq cr
    integReq = fromReq ir
    availReq = fromReq ar

-- | NVD classification
data Severity = Low | Medium | High

-- | Convert a Score into a Severity
fromScore :: Score -> Severity
fromScore s
    | s <= 3.9  = Low
    | s <= 6.9  = Medium
    | otherwise = High

-- | Convert a Severity in its String representation
fromSeverity :: Severity -> String
fromSeverity Low = "Low"
fromSeverity Medium = "Medium"
fromSeverity High = "High"
