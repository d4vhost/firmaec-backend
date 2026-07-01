package ec.eeasa.firmaec.controller;

import ec.eeasa.firmaec.service.FirmaECService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/firma")
@CrossOrigin(origins = "*")
public class FirmaCentralizadaController {

    private static final Logger LOGGER = Logger.getLogger(FirmaCentralizadaController.class.getName());
    private final FirmaECService firmaECService;

    public FirmaCentralizadaController(FirmaECService firmaECService) {
        this.firmaECService = firmaECService;
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
}
