package ec.eeasa.firmaec.controller;

import ec.eeasa.firmaec.service.FirmaECService;
import ec.eeasa.firmaec.service.VerificacionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/firma")
@CrossOrigin(origins = {"http://localhost:4200", "http://127.0.0.1:4200", "https://localhost:4200", "https://127.0.0.1:4200"})
public class FirmaCentralizadaController {

    private static final Logger LOGGER = Logger.getLogger(FirmaCentralizadaController.class.getName());
    private final FirmaECService firmaECService;
    private final VerificacionService verificacionService;

    public FirmaCentralizadaController(FirmaECService firmaECService, VerificacionService verificacionService) {
        this.firmaECService = firmaECService;
        this.verificacionService = verificacionService;
    }

    @PostMapping("/firmar")
    public ResponseEntity<Map<String, String>> firmarDocumentoDirecto(@RequestBody FirmaRequest request) {
        LOGGER.info("Petición recibida en /api/firma/firmar");
        
        // Validación básica de seguridad
        if (request.getPdfBase64() == null || request.getP12Base64() == null || request.getPassword() == null) {
            LOGGER.warning("Faltan parámetros requeridos para la firma.");
            return ResponseEntity.badRequest().build();
        }

        try {
            // Pasamos los datos al servicio para que gestione la comunicación con MINTEL
            String pdfFirmado = firmaECService.firmarDocumento(
                    request.getPdfBase64(), 
                    request.getP12Base64(), 
                    request.getPassword(),
                    request.getPagina(),
                    request.getPosX(),
                    request.getPosY()
            );

            // Una vez que tenemos la firma, devolvemos el PDF firmado
            Map<String, String> response = new HashMap<>();
            response.put("pdfFirmado", pdfFirmado);
            
            // Limpieza inmediata en el request dto (Best Effort Security)
            request.setPassword(null);
            request.setP12Base64(null);

            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            LOGGER.severe("Error procesando la firma electrónica");
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/verificar")
    public ResponseEntity<Map<String, Object>> verificarDocumento(@RequestBody Map<String, String> request) {
        LOGGER.info("Petición recibida en /api/firma/verificar");

        String pdfBase64 = request.get("pdfBase64");
        if (pdfBase64 == null || pdfBase64.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        try {
            List<Map<String, Object>> firmantes = verificacionService.verificarDocumento(pdfBase64);

            Map<String, Object> response = new HashMap<>();
            response.put("totalFirmantes", firmantes.size());
            response.put("firmantes", firmantes);
            response.put("tieneFirma", !firmantes.isEmpty());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            LOGGER.severe("Error verificando documento: " + e.getMessage());
            Map<String, Object> errorResp = new HashMap<>();
            errorResp.put("error", "Error al verificar el documento.");
            return ResponseEntity.internalServerError().body(errorResp);
        }
    }

    @PostMapping("/validar-certificado")
    public ResponseEntity<Map<String, Object>> validarCertificado(@RequestBody Map<String, String> request) {
        LOGGER.info("Petición recibida en /api/firma/validar-certificado");

        String p12Base64 = request.get("p12Base64");
        String password = request.get("password");

        if (p12Base64 == null || p12Base64.isEmpty() || password == null) {
            return ResponseEntity.badRequest().build();
        }

        try {
            byte[] p12Bytes = java.util.Base64.getDecoder().decode(p12Base64);
            // Limitar tamaño del certificado (máx 50KB)
            if (p12Bytes.length > 50 * 1024) {
                Map<String, Object> errorResp = new HashMap<>();
                errorResp.put("valido", false);
                errorResp.put("message", "El archivo del certificado es demasiado grande.");
                return ResponseEntity.badRequest().body(errorResp);
            }
            Map<String, Object> response = verificacionService.validarCertificadoP12(p12Bytes, password);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            LOGGER.warning("Error validando certificado: " + e.getMessage());
            Map<String, Object> errorResp = new HashMap<>();
            errorResp.put("valido", false);
            // Mensaje genérico sin exponer detalles internos
            errorResp.put("message", "Certificado inválido o contraseña incorrecta.");
            return ResponseEntity.ok(errorResp);
        }
    }
}
