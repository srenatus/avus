module Rivum (processScan, defaultConfig) where

import qualified Config.Dyre as Dyre
import qualified Config.Dyre.Options as Dyre
import Config.Dyre.Relaunch

import System.Environment (getArgs)
import Rivum.SecurityConcept
import qualified Rivum.CodeModel as CM

data Config = Config
              { securityConcept :: SecurityConcept
	      , codeMap :: CM.CodeMap
	      , err :: Maybe String
	      }

-- readScan = undefined

realMain Config{ err = Just err }       = putStrLn $ "realMain here, error: " ++ err
realMain Config{ securityConcept = sc
               , codeMap         = cm } = putStrLn $ "realMain here, all good"

showError c str = c { err = Just str }

defaultConfig = Config { securityConcept = undefined
                       , codeMap         = undefined
                       , err             = Nothing
		       }

processScan :: Config -> IO ()
processScan cfg = do
  args <- Dyre.withDyreOptions Dyre.defaultParams getArgs

  Dyre.wrapMain Dyre.defaultParams
    { Dyre.projectName = "rivum"
    , Dyre.realMain    = realMain
    , Dyre.showError   = showError
    } cfg

-- main = do
--   (file:_) <- getArgs
--   let dom = classify file codeMap
--   putStrLn $ show dom
