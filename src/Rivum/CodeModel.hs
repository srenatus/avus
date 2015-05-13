{-# LANGUAGE TupleSections #-}
module Rivum.CodeModel
  ( Domain(..)
  , CodeMap
  , classify
  , codeMap
  ) where

import qualified Data.Map.Strict as M

data Domain = Userland
            | Kernel
	    | Misc
	      deriving (Eq, Show)

type CodeMap = M.Map FilePath Domain

classify :: FilePath -> CodeMap -> Maybe Domain
classify f cm = M.lookup f cm

codeMap :: CodeMap
codeMap = M.fromList $ concat [userland, kernel, misc]
  where
    userland = map (,Userland) ["rm.c", "mkdir.c"]
    kernel = map (,Kernel) ["mem.c"]
    misc = map (,Misc) ["sh.c", "init.c"]
