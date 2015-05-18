module Rivum where
import qualified Rivum as R
import qualified Rivum.CVSS as CVSS

data Requirements = (Req, Req, Req) -- Confidentiality, Integrity, Availability
data SecurityConcept = Domain -> Requirements

xv6Concept :: SecurityConcept
xv6Concept dom = undefined

xv6Config = R.defaultConfig
    { baseUpdate = undefined
    , envUpdate = undefined
    }

main = R.processScan xv6Config
