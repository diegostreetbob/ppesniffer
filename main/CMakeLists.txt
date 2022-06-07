set(COMPONENT_SRCS "main.c" "wifi.c" "mqtt.c")
set(COMPONENT_ADD_INCLUDEDIRS ".")

set(COMPONENT_EMBED_TXTFILES
    "certs/ca.pem"
    "certs/client.pem"
    "certs/client.key"
)

register_component()