#!/bin/zsh
vault secrets enable -path=object-store os2
vault write object-store/config username=vaultecsadmin password=azerty url=http://0.0.0.0:8080 skip_ssl=true