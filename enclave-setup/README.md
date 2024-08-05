## Steps to start the zkBob generator 

1. Build the EIF file and start the oyster enclave.
   ```
   ./build.sh
   ```


2. Register the generator with the help of KalypsoSDK
   ```
   yarn test ./test/generatorOperations/1_register.ts
   ```

3. Stake tokens with the help of KalypsoSDK
   ```
   yarn test ./test/generatorOperations/2_stake.ts
   ```

4. Join a marketplace with the help of KalypsoSDK
   ```
   yarn test ./test/generatorOperations/3_join_market_place.ts
   ```

5. Update the ECIES key with the help of KalypsoSDK
    ```
   yarn test ./test/generatorOperations/4_update_ecies_key.ts
    ```
6. Generate the config setup by making an HTTP call to the generator client:
    ```
   curl --location --request POST 'http://3.109.54.190:5000/api/generatorConfigSetup' \
   --header 'Content-Type: application/json' \
   --data-raw '{
       "generator_config": [
       {
         "address": "0x0469866e13cd7DF08f5482FBb127a72fF197365D",
         "data": "Some data",
         "supported_markets": [
           "1"
         ]
       }
     ],
   
     "runtime_config": {
       "ws_url": "wss://arb-sepolia.g.alchemy.com/v2/WPcL0MatIn2ai-4O6BcJgfeuXqD7WxRi",
       "http_url": "https://arb-sepolia.g.alchemy.com/v2/WPcL0MatIn2ai-4O6BcJgfeuXqD7WxRi",
       "start_block":29108940,
       "private_key": "91e60908ad659c964169211f07d7c2328ca8919d81dfd772c850bebfd67d4cdf",
       "chain_id": 421614,
       "payment_token": "0x01d84D33CC8636F83d2bb771e184cE57d8356863",
       "staking_token": "0xdb69299dDE4A00c99b885D9f8748B2AeD1Fe4Ed4",
       "attestation_verifier": "0x3aB3487269206d5f6a10725d4e477BaA3611adcA",
       "entity_registry": "0xBf6AfC0dB112e1e330Ea3fF4640Bac5fBA3e4B65",
       "proof_market_place": "0x81C80965f4E1b073858cc9D55d7D9A517C9fF258",
       "generator_registry": "0x2CcCb1ac0fa40922bc800619E09fc3bD821ea4F8",
       "markets":{
           "5":{
               "port":"3030",
               "ivs_url":"http://3.109.54.190:3000"
           }
       }
     }
   
   }'
    ```
7. Start the zkbob-generator by invoking the following API call
    ```
    curl --location --request POST 'http://3.109.54.190:5000/api/startProgram' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "program_name":"zkbob-generator"
    }'
    ```
8. Start the kalypso-listener by invoking the following API call
    ```
    curl --location --request POST 'http://3.109.54.190:5000/api/startProgram' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "program_name":"listener"
    }'
    ```


--------
curl --location --request GET 'http://3.109.54.190:5000/api/benchmark?market_id=6'
