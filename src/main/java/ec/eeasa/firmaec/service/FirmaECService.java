package ec.eeasa.firmaec.service;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@Service
public class FirmaECService {

    private static final Logger LOGGER = Logger.getLogger(FirmaECService.class.getName());
    
    // URL de la API REST Centralizada de MINTEL. 
    // Para producción puede variar a https://api.firmadigital.gob.ec/api/firmadigital/pdf/documento
    private final String MINTEL_API_URL = "https://api.firmadigital.gob.ec/api/firmadigital/pdf/documento";

    public String firmarDocumento(String pdfBase64, String p12Base64, String password) {
        LOGGER.info("Iniciando proceso de firma centralizada. Se recibió el documento y las credenciales.");
        
        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // Construir el payload tal como lo exige MINTEL
            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("documento", pdfBase64);
            requestBody.put("certificado", p12Base64);
            requestBody.put("password", password);
            
            // Opcional: Coordenadas de firma para el PDF
            // requestBody.put("pagina", "1");
            // requestBody.put("posicionX", "100");
            // requestBody.put("posicionY", "100");

            HttpEntity<Map<String, String>> request = new HttpEntity<>(requestBody, headers);
            
            LOGGER.info("Enviando petición de firma a MINTEL...");
            
            // POST a la API
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    MINTEL_API_URL, 
                    request, 
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                LOGGER.info("Firma completada exitosamente en los servidores de MINTEL.");
                
                // Limpiar la clave y p12 de memoria explícitamente si fuera posible, 
                // aunque Java Garbage Collector lo manejará. No dejamos rastros en Logs.
                return (String) response.getBody().get("documento");
            } else {
                LOGGER.severe("Error al firmar en MINTEL: " + response.getStatusCode());
                throw new RuntimeException("Error en la firma electrónica");
            }

        } catch (Exception e) {
            LOGGER.severe("Excepción al intentar firmar: MINTEL rechazó las credenciales o el servicio no está disponible.");
            // No imprimimos e.getMessage() si contiene info sensible, aunque RestTemplate suele ocultar el body
            throw new RuntimeException("Error de comunicación con MINTEL o credenciales inválidas");
        }
    }
}
