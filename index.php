<?php

use GuzzleHttp\Client;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

require 'vendor/autoload.php';

$serviceAccount = json_decode(file_get_contents('service-account.json'));

$jwk = new JWK((array)$serviceAccount->jwk);

$algorithmManager = new AlgorithmManager([
    new ES512()
]);

$jwsBuilder = new JWSBuilder($algorithmManager);

$payload = json_encode([
    "iss" => $serviceAccount->issuer,
    "sub" => $serviceAccount->sub,
    "aud" => $serviceAccount->audience,
    "iat" => time(),
    "exp" => time() + 5,
    'jti' => Ramsey\Uuid\v4()
]);

$jws = $jwsBuilder
    ->create()
    ->withPayload($payload)
    ->addSignature($jwk, ['alg' => 'ES512'])
    ->build();

$serializer = new CompactSerializer();

$token = $serializer->serialize($jws, 0);

$client = new Client();

$response = $client->request('POST', $serviceAccount->token_endpoint, [
    'verify' => false,
    'auth' => [$serviceAccount->client_id, $serviceAccount->client_secret, 'basic'],
    'form_params' => [
        'grant_type' => $serviceAccount->grant_type,
        'scope' => implode(' ', $serviceAccount->scope),
        'assertion' => $token
    ]
]);

$tokenResponse = json_decode($response->getBody()->getContents());

var_dump($tokenResponse);

$employeeResponse = $client->request('GET', 'https://mitarbeiterwebservice-maklerinfo.inte.dionera.dev/service/ari/employee/1.0/rest/' . $serviceAccount->sub, [
    'verify' => false,
    'headers' => [
        'Authorization' => 'Bearer ' . $tokenResponse->access_token,
        'Accept'        => 'application/json',
    ]
]);

var_dump($employeeResponse->getBody()->getContents());
