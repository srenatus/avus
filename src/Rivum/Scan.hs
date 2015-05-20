{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module Rivum.Scan
    ( processData
    , processVuln
    , Vuln
    )where

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as B
import Prelude hiding (mapM)
import Data.Foldable (for_)
import Data.Traversable (mapM)
import Data.Csv (ToNamedRecord, FromNamedRecord, Header, encodeByNameWith, defaultEncodeOptions, EncodeOptions(..))
import Data.Csv.Streaming
import GHC.Generics

import qualified Rivum.CWE as CWE
import qualified Rivum.CVSS as CVSS

data Vuln = Vuln
    { vuln_id   :: String
    , name      :: String
    , garbage   :: String
    , cwe_name  :: String
    , cwe_id    :: Maybe CWE.Id
    , severity  :: String
    , file      :: FilePath
    , path      :: FilePath
    , parameter :: String
    , line_no   :: Integer
    } deriving (Eq, Show, Generic)

instance FromNamedRecord Vuln
instance ToNamedRecord Vuln

processData :: FilePath  -- scan file
            -> (Vuln -> IO Vuln)
            -> IO () -- (Records Vuln)
processData fp f = do
    csvData <- BL.readFile fp
    let (Right (hdr, rs)) = decodeByName csvData :: Either String (Header, Records Vuln)
    mapM f rs
    vs <- mapM f rs -- :: Records Vuln
    for_ vs (\x -> B.putStr $ encodeByNameWith encodeOpts hdr [x])
    putStrLn "done"
  where
    encodeOpts = defaultEncodeOptions
        { encUseCrLf       = False
        , encIncludeHeader = False
        }

processVuln :: (FilePath -> CVSS.Base -> IO CVSS.Base)
            -> (FilePath -> CVSS.Temp -> IO CVSS.Temp)
            -> (FilePath -> CVSS.Env -> IO CVSS.Env)
            -> Vuln
            -> IO Vuln
processVuln baseUpdate tempUpdate envUpdate v@(Vuln vid n g cn (Just cweId) s file p pm l ) = do
    base <- baseUpdate file $ CWE.cweImpact cweId CVSS.defaultBase
    temp <- tempUpdate file CVSS.defaultTemp
    env  <- envUpdate file CVSS.defaultEnv
    let score    = CVSS.env base temp env
        severity = CVSS.fromSeverity $ CVSS.fromScore score
    -- putStrLn $ vid ++ " is " ++ (show cweId) ++ " in " ++ file ++ " and has " ++ severity
    return (Vuln vid n g cn (Just cweId) severity file p pm l)
processVuln _ _ _ v = return v
