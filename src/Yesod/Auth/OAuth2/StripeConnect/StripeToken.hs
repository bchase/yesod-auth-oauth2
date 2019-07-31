{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
module Yesod.Auth.OAuth2.StripeConnect.StripeToken
    ( StripeToken (..)
    , fetch
    , stripeExtra
    ) where

import Data.Aeson
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Network.HTTP.Conduit (Manager, Request (method), Response (responseBody), parseRequest, urlEncodedBody, httpLbs)
import Network.OAuth.OAuth2

stripeDecode :: FromJSON a => LBS.ByteString -> Either String a
stripeDecode str = case decode str of
  Nothing -> Left ("`stripeDecode` failed for: " ++ show str)
  Just x  -> Right x

stripeExtra :: StripeToken -> [(Text, Text)]
stripeExtra StripeToken{..} =
  [ ( "stripe_user_id", stripeUserId           )
  , ( "access_token",   accessToken            )
  , ( "refresh_token",  refreshToken           )
  , ( "token_type",     tokenType              )
  , ( "scope",          scope                  )
  , ( "livemode",       T.pack $ show livemode )
  ]

data StripeToken = StripeToken
  { stripeUserId :: Text
  , accessToken :: Text
  , refreshToken :: Text
  , tokenType :: Text
  , scope :: Text
  , livemode :: Bool
  } deriving ( Show )

instance FromJSON StripeToken where
  parseJSON = withObject "StripeToken" $ \o -> StripeToken
    <$> o .: "stripe_user_id"
    <*> o .: "access_token"
    <*> o .: "refresh_token"
    <*> o .: "token_type"
    <*> o .: "scope"
    <*> o .: "livemode"


fetch :: OAuth2 -> Text -> Text -> Manager -> IO (Either String StripeToken)
fetch oauth2 csrf code manager = do
  resp <- do
    bareReq <- parseRequest "https://connect.stripe.com/oauth/token"
    let params =
          [ ("client_secret", encodeUtf8 (oauthClientSecret oauth2))
          , ("grant_type", "authorization_code")
          , ("code", encodeUtf8 code)
          , ("state", encodeUtf8 csrf)
          ]
        postReq = bareReq { method = "POST"}
        req = urlEncodedBody params postReq
    httpLbs req manager

  pure $ stripeDecode $ responseBody resp
