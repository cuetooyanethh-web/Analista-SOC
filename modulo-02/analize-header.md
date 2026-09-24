

# Análisis de Cabeceras en MXToolbox 2.1

## Evidencia de Cabecera Recibida
```text
Received: from correo-proveedores.net (correo-proveedores.net)
    by ://ferreteriaelmartillo.com.pe (Postfix) with ESMTPS id 7c1a9
    for <compras@ferreteriaelmartillo.com.pe>; Tue, 10 Jun 2026 09:41:03 -0500 (PET)
Authentication-Results: ://ferreteriaelmartillo.com.pe;
    spf=softfail (sender IP is 193.34.108.52) smtp.mailfrom=correo-proveedores.net;
    dkim=fail (signature verification failed);
    dmarc=fail (p=none) header.from=correo-proveedores.net
From: "Proveedor Aceros del Sur SAC" <facturacion@correo-proveedores.net>
Reply-To: "Cobranzas" <pagos@secure-proveedores-pe.com>
To: compras@ferreteriaelmartillo.com.pe
Subject: Factura pendiente N° 4471 - actualice los datos de pago antes del viernes
Date: Tue, 10 Jun 2026 09:41:01 -0500
Message-ID: <4471-factura@correo-proveedores.net>
```

## Puntos Críticos Detectados (Hallazgos de Seguridad)

* **Fallo en Autenticación Global**: El correo electrónico ha fallado de forma contundente en las tres principales validaciones de seguridad de correo electrónico:
  * **`spf=softfail`**: La dirección IP de origen (`193.34.108.52`) no está explícitamente autorizada para enviar correos en nombre de ese dominio.
  * **`dkim=fail`**: La firma digital de verificación ha fallado, lo que significa que el mensaje pudo haber sido alterado en el camino.
  * **`dmarc=fail`**: Al no alinearse ni SPF ni DKIM, el protocolo DMARC determina que el remitente no es legítimo.
* **Remitente Falso (Spoofing)**: El campo `From` simula ser "Proveedor Aceros del Sur SAC", pero la dirección técnica real es `<facturacion@correo-proveedores.net>`, un dominio genérico que no pertenece a la empresa oficial.
* **Táctica de Desvío (`Reply-To`)**: Si se responde al correo, las respuestas irán dirigidas automáticamente a `<pagos@secure-proveedores-pe.com>`, un correo diseñado específicamente para simular un entorno de pagos seguro y completar el fraude.

---


[<- Volver al Dossier Técnico](/modulo-02/dossier-tecnico-m2.md)