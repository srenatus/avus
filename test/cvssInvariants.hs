{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TemplateHaskell #-}
import Test.QuickCheck
import Test.QuickCheck
import Data.DeriveTH
import Rivum.CVSS

$( derive makeArbitrary ''Av )
$( derive makeArbitrary ''Ac )
$( derive makeArbitrary ''Au )
$( derive makeArbitrary ''Imp )
$( derive makeArbitrary ''Base )
$( derive makeArbitrary ''E )
$( derive makeArbitrary ''Rl )
$( derive makeArbitrary ''Rc )
$( derive makeArbitrary ''Temp )

prop_defaultTemp_invariant :: Base -> Bool
prop_defaultTemp_invariant b = base b == temp b defaultTemp

prop_defaultEnv_invariant :: Base -> Temp -> Bool
prop_defaultEnv_invariant b t = temp b t == env b t defaultEnv

return []
main = $(quickCheckAll)
