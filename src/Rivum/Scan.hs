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

data Vuln = Vuln
    { vuln_id   :: String
    , name      :: String
    , garbage   :: String
    , cwe_name  :: String
    , cwe_id    :: CWE.Id
    , severity  :: String
    , file      :: FilePath
    , path      :: FilePath
    , parameter :: String
    , line_no   :: Integer
    } deriving (Eq, Show, Generic)

instance FromNamedRecord Vuln
instance ToNamedRecord Vuln

processData :: FilePath -> (Vuln -> IO Vuln) -> IO () -- (Records Vuln)
processData fp f = do
    csvData <- BL.readFile fp
    let (Right (hdr, rs)) = decodeByName csvData :: Either String (Header, Records Vuln)
    mapM f rs
    vs <- mapM f rs -- :: Records Vuln
    for_ vs (\x -> B.putStr $ encodeByNameWith encodeOpts hdr [x]) -- TODO prints header each time!
  where
    encodeOpts = defaultEncodeOptions
        { encUseCrLf       = False
	, encIncludeHeader = False
	}

processVuln :: Vuln -> IO Vuln
processVuln v@(Vuln vid n g cn cwe_id s file p pm l ) = do
    putStrLn $ vid ++ " is " ++ (show cwe_id) ++ " in " ++ file
    return (Vuln vid n g cn (cwe_id + 10) s file p pm l)
