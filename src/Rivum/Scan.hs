{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}
module Rivum.Scan
    ( processData
    , processVuln
    , Vuln
    )where

import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as B
import Prelude hiding (mapM, putStr)
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

-- | Input helper function
--   defaults to stdin
readData :: Maybe FilePath -> IO BL.ByteString
readData Nothing   = BL.getContents
readData (Just fp) = BL.readFile fp

-- | Output helper function
--   defaults to stdout
putStr :: Maybe FilePath -> BL.ByteString -> IO ()
putStr Nothing   = B.putStr
putStr (Just fp) = BL.appendFile fp

processData :: Maybe FilePath  -- input, scan file
            -> Maybe FilePath  -- output
            -> (Vuln -> IO Vuln)
            -> IO () -- (Records Vuln)
processData fp out f = do
    csvData <- readData fp
    let (Right (hdr, rs)) = decodeByName csvData :: Either String (Header, Records Vuln)
    mapM f rs
    vs <- mapM f rs -- :: Records Vuln
    for_ vs (\x -> putStr out $ encodeByNameWith encodeOpts hdr [x])
    -- putStrLn "done"
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
    return (Vuln vid n g cn (Just cweId) severity file p pm l)
processVuln _ _ _ v = return v
