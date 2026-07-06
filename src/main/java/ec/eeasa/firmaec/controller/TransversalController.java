package ec.eeasa.firmaec.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/transversal")
@CrossOrigin(origins = {"http://localhost:4200", "http://127.0.0.1:4200", "https://localhost:4200", "https://127.0.0.1:4200", "https://app.eeasa.com.ec:7001", "https://app.eeasa.com.ec"})
public class TransversalController {

    private static final Logger LOGGER = Logger.getLogger(TransversalController.class.getName());

    // Almacenamiento temporal con timestamp para expiración automática
    private final Map<String, TokenData> baseDatosTemporal = new ConcurrentHashMap<>();

    // Tiempo máximo de vida de un token: 10 minutos
    private static final long TOKEN_TTL_MS = 10 * 60 * 1000;

    // Tamaño máximo de documento: 20MB en Base64
    private static final int MAX_BASE64_LENGTH = 20 * 1024 * 1024;

    private static class TokenData {
        final String base64;
        final long createdAt;

        TokenData(String base64) {
            this.base64 = base64;
            this.createdAt = System.currentTimeMillis();
        }

        boolean isExpired() {
            return (System.currentTimeMillis() - createdAt) > TOKEN_TTL_MS;
        }
    }

    // Limpieza de tokens expirados (se ejecuta en cada petición)
    private void limpiarTokensExpirados() {
        Iterator<Map.Entry<String, TokenData>> it = baseDatosTemporal.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().isExpired()) {
                it.remove();
            }
        }
    }

    // 1. Angular envía el PDF en Base64 aquí y recibe un Token único
    @PostMapping("/subir")
    public ResponseEntity<Map<String, String>> subirDocumentoDesdeAngular(@RequestBody Map<String, String> payload) {
        limpiarTokensExpirados();

        String base64 = payload.get("base64");
        if (base64 == null || base64.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        // Validar tamaño máximo
        if (base64.length() > MAX_BASE64_LENGTH) {
            LOGGER.warning("Documento rechazado: excede el tamaño máximo permitido.");
            Map<String, String> error = new HashMap<>();
            error.put("error", "El documento excede el tamaño máximo permitido (20MB).");
            return ResponseEntity.badRequest().body(error);
        }

        String token = UUID.randomUUID().toString();
        baseDatosTemporal.put(token, new TokenData(base64));
        LOGGER.info("Token generado: " + token.substring(0, 8) + "... (expira en 10 min)");

        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        return ResponseEntity.ok(response);
    }

    // 2. La aplicación FirmaEC de escritorio hace un GET aquí para leer el documento
    @GetMapping("/{token}")
    public ResponseEntity<Map<String, Object>> firmaEcObtenerDocumento(@PathVariable String token) {
        limpiarTokensExpirados();

        TokenData data = baseDatosTemporal.get(token);

        // Validar que el token exista y no haya expirado
        if (data == null || data.isExpired()) {
            if (data != null) baseDatosTemporal.remove(token); // Limpiar si expiró
            LOGGER.warning("Token no encontrado o expirado: " + token.substring(0, Math.min(8, token.length())) + "...");
            return ResponseEntity.notFound().build();
        }

        // Estructura JSON estricta requerida por MINTEL para devolver el documento
        Map<String, Object> documento = new HashMap<>();
        documento.put("nombre", "documento_eeasa.pdf");
        documento.put("documento", data.base64);

        Map<String, Object> response = new HashMap<>();
        response.put("documentos", new Object[]{documento});

        return ResponseEntity.ok(response);
    }

    // 3. La aplicación FirmaEC de escritorio hace un PUT aquí para devolver el PDF ya firmado
    @PutMapping("/{token}")
    public ResponseEntity<String> firmaEcRecibirFirmado(@PathVariable String token, @RequestParam("base64") String base64Firmado) {
        limpiarTokensExpirados();

        // Validar que el token original exista
        if (!baseDatosTemporal.containsKey(token)) {
            LOGGER.warning("Intento de PUT con token inexistente.");
            return ResponseEntity.notFound().build();
        }

        // Eliminar el token original (uso único)
        baseDatosTemporal.remove(token);

        // Guardar el firmado con su propio token temporal
        baseDatosTemporal.put(token + "_firmado", new TokenData(base64Firmado));
        return ResponseEntity.ok("Documento firmado y recibido correctamente en la EEASA");
    }
}