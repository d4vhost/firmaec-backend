package ec.eeasa.firmaec.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/transversal")
@CrossOrigin(origins = "*")
public class TransversalController {

    // Simula el almacenamiento temporal del documento (En producción usar DB o FileSystem)
    private Map<String, String> baseDatosTemporal = new ConcurrentHashMap<>();

    // 1. Angular envía el PDF en Base64 aquí y recibe un Token único
    @PostMapping("/subir")
    public ResponseEntity<Map<String, String>> subirDocumentoDesdeAngular(@RequestBody Map<String, String> payload) {
        String token = UUID.randomUUID().toString();
        baseDatosTemporal.put(token, payload.get("base64"));
        
        Map<String, String> response = new HashMap<>();
        response.put("token", token);
        return ResponseEntity.ok(response);
    }

    // 2. La aplicación FirmaEC de escritorio hace un GET aquí para leer el documento
    @GetMapping("/{token}")
    public ResponseEntity<Map<String, Object>> firmaEcObtenerDocumento(@PathVariable String token) {
        String base64 = baseDatosTemporal.get(token);
        
        // Estructura JSON estricta requerida por MINTEL para devolver el documento
        Map<String, Object> documento = new HashMap<>();
        documento.put("nombre", "documento_eeasa.pdf");
        documento.put("documento", base64);
        
        Map<String, Object> response = new HashMap<>();
        response.put("documentos", new Object[]{documento});
        
        return ResponseEntity.ok(response);
    }

    // 3. La aplicación FirmaEC de escritorio hace un PUT aquí para devolver el PDF ya firmado
    @PutMapping("/{token}")
    public ResponseEntity<String> firmaEcRecibirFirmado(@PathVariable String token, @RequestParam("base64") String base64Firmado) {
        // El documento ya está firmado. Aquí lo procesas y lo guardas en la base de datos de Oracle
        baseDatosTemporal.put(token + "_firmado", base64Firmado);
        return ResponseEntity.ok("Documento firmado y recibido correctamente en la EEASA");
    }
}