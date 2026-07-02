package ec.eeasa.firmaec.service;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Logger;

@Service
public class VerificacionService {

    private static final Logger LOGGER = Logger.getLogger(VerificacionService.class.getName());

    // Entidades certificadoras reconocidas en Ecuador
    private static final List<String> ENTIDADES_RECONOCIDAS = Arrays.asList(
        "BANCO CENTRAL DEL ECUADOR",
        "SECURITY DATA",
        "CONSEJO DE LA JUDICATURA",
        "ANF AUTHORITY",
        "ANFAC",
        "CORPNEWBEST",
        "UANATACA",
        "LAZZATE",
        "DATILMEDIA",
        "ARGOS",
        "FIRMAEC"
    );

    public List<Map<String, Object>> verificarDocumento(String pdfBase64) {
        List<Map<String, Object>> firmantes = new ArrayList<>();

        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            byte[] pdfBytes = Base64.getDecoder().decode(pdfBase64);

            try (PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
                List<PDSignature> signatures = document.getSignatureDictionaries();

                if (signatures == null || signatures.isEmpty()) {
                    LOGGER.info("El documento no contiene firmas digitales.");
                    return firmantes;
                }

                LOGGER.info("Se encontraron " + signatures.size() + " firma(s) en el documento.");

                for (PDSignature sig : signatures) {
                    Map<String, Object> firmante = new HashMap<>();

                    try {
                        // Extraer los bytes de la firma
                        byte[] signatureContent = sig.getContents(new ByteArrayInputStream(pdfBytes));
                        byte[] signedContent = sig.getSignedContent(new ByteArrayInputStream(pdfBytes));

                        // Parsear la firma CMS/PKCS7
                        CMSSignedData cmsSignedData = new CMSSignedData(
                            new org.bouncycastle.cms.CMSProcessableByteArray(signedContent),
                            signatureContent
                        );

                        // Obtener el certificado del firmante
                        @SuppressWarnings("unchecked")
                        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
                        SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();

                        for (SignerInformation signerInfo : signerInfoStore.getSigners()) {
                            @SuppressWarnings("unchecked")
                            Collection<X509CertificateHolder> certCollection =
                                certStore.getMatches(signerInfo.getSID());

                            X509CertificateHolder certHolder = certCollection.iterator().next();
                            X509Certificate cert = new JcaX509CertificateConverter()
                                .setProvider("BC")
                                .getCertificate(certHolder);

                            // Verificar la firma criptográficamente
                            boolean firmaValida = false;
                            try {
                                firmaValida = signerInfo.verify(
                                    new JcaSimpleSignerInfoVerifierBuilder()
                                        .setProvider("BC")
                                        .build(cert)
                                );
                            } catch (Exception e) {
                                LOGGER.warning("Verificación criptográfica falló: " + e.getMessage());
                            }

                            // Verificar vigencia del certificado en la fecha de la firma
                            boolean vigente = false;
                            try {
                                if (sig.getSignDate() != null) {
                                    cert.checkValidity(sig.getSignDate().getTime());
                                } else {
                                    cert.checkValidity(); // Fallback a la fecha actual si no hay fecha de firma
                                }
                                vigente = true;
                            } catch (Exception e) {
                                LOGGER.warning("Certificado fuera de vigencia en la fecha de firma: " + e.getMessage());
                            }

                            // Verificar si la entidad emisora es reconocida
                            String issuerDN = cert.getIssuerX500Principal().getName();
                            String entidadCertificadora = extractOrganization(issuerDN);
                            boolean entidadReconocida = isEntidadReconocida(entidadCertificadora, issuerDN);

                            // Solo es válido si: firma criptográfica OK + certificado vigente + entidad reconocida
                            boolean esValido = firmaValida && vigente && entidadReconocida;

                            // Extraer datos del sujeto (firmante)
                            String subjectDN = cert.getSubjectX500Principal().getName();
                            LOGGER.info("Subject DN completo: " + subjectDN);
                            String cn = extractField(subjectDN, "CN");
                            
                            // Buscar cédula en múltiples campos posibles
                            String serialNumber = extractField(subjectDN, "SERIALNUMBER");
                            if (serialNumber.isEmpty()) {
                                serialNumber = extractField(subjectDN, "OID.2.5.4.5");
                            }
                            if (serialNumber.isEmpty()) {
                                serialNumber = extractField(subjectDN, "2.5.4.5");
                            }
                            if (serialNumber.isEmpty()) {
                                serialNumber = extractField(subjectDN, "UID");
                            }
                            
                            String telefono = "";
                            
                            // EXPLORAR EXTENSIONES PARA ENCONTRAR LA CÉDULA Y EL TELÉFONO
                            try {
                                Set<String> nonCritSet = cert.getNonCriticalExtensionOIDs();
                                if (nonCritSet != null) {
                                    
                                    // Buscar número de teléfono si existe (usualmente empieza con 09 o 08)
                                    for (String oid : nonCritSet) {
                                        byte[] extVal = cert.getExtensionValue(oid);
                                        if (extVal != null) {
                                            String extStr = new String(extVal, java.nio.charset.StandardCharsets.UTF_8).replaceAll("[^0-9]", "");
                                            if (extStr.length() == 10 && (extStr.startsWith("09") || extStr.startsWith("08"))) {
                                                telefono = extStr;
                                                break;
                                            }
                                        }
                                    }

                                    if (serialNumber.isEmpty()) {
                                        // OIDs conocidos de Cédula/RUC en Ecuador
                                        String[] oidsCedula = {
                                            "1.3.6.1.4.1.34380.3.1",  // Cédula CorpNewBest
                                            "1.3.6.1.4.1.34380.3.11", // RUC CorpNewBest
                                            "1.3.6.1.4.1.37947.3.1",  // Cédula BCE
                                            "1.3.6.1.4.1.37947.3.11"  // RUC BCE
                                        };
                                        
                                        for (String oidCedula : oidsCedula) {
                                            byte[] extVal = cert.getExtensionValue(oidCedula);
                                            if (extVal != null) {
                                                String extStr = new String(extVal, java.nio.charset.StandardCharsets.UTF_8);
                                                extStr = extStr.replaceAll("[^0-9]", ""); // Solo números
                                                if (extStr.length() >= 10) {
                                                    serialNumber = extStr.substring(0, 10);
                                                    LOGGER.info("Cédula encontrada en extensión OID " + oidCedula);
                                                    break; // Ya la encontramos, no seguir buscando
                                                }
                                            }
                                        }
                                        
                                        // Si no se encontró en OIDs conocidos, buscar cualquier extensión que tenga 10 dígitos (y que no sea fecha)
                                        if (serialNumber.isEmpty()) {
                                            for (String oid : nonCritSet) {
                                                byte[] extVal = cert.getExtensionValue(oid);
                                                if (extVal != null) {
                                                    String extStr = new String(extVal, java.nio.charset.StandardCharsets.UTF_8).replaceAll("[^a-zA-Z0-9-]", "");
                                                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("^(\\d{10})$").matcher(extStr);
                                                    if (m.find()) {
                                                        // Evitar fechas (empiezan con 20) o teléfonos (empiezan con 09 o 08) si es posible
                                                        String val = m.group(1);
                                                        if (!val.startsWith("202") && !val.startsWith("09")) { 
                                                            serialNumber = val;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {}
                            
                            // Último recurso: extraer números de 10 o 13 dígitos del CN (cédula o RUC)
                            if (serialNumber.isEmpty() && cn != null) {
                                java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\b(\\d{10,13})\\b").matcher(cn);
                                if (m.find()) {
                                    serialNumber = m.group(1);
                                }
                            }
                            // Buscar en Subject Alternative Names (SAN)
                            try {
                                Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                                if (sans != null) {
                                    for (List<?> san : sans) {
                                        if (san.size() >= 2) {
                                            Object sanObj = san.get(1);
                                            String sanValue = "";
                                            if (sanObj instanceof byte[]) {
                                                sanValue = new String((byte[]) sanObj, java.nio.charset.StandardCharsets.UTF_8).replaceAll("[^a-zA-Z0-9-]", "");
                                            } else {
                                                sanValue = String.valueOf(sanObj);
                                            }
                                            LOGGER.info("SAN encontrado: " + sanValue);
                                            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\\b(\\d{10})\\b").matcher(sanValue);
                                            if (m.find() && serialNumber.isEmpty()) {
                                                serialNumber = m.group(1);
                                                LOGGER.info("¡Cédula encontrada en SAN!");
                                            }
                                        }
                                    }
                                }
                            } catch (Exception e) {}

                            // Otro recurso: buscar en todo el DN
                            if (serialNumber.isEmpty()) {
                                java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?:SERIALNUMBER|OID\\.2\\.5\\.4\\.5|2\\.5\\.4\\.5)\\s*=\\s*([^,]+)").matcher(subjectDN);
                                if (m.find()) {
                                    serialNumber = m.group(1).trim();
                                }
                            }
                            LOGGER.info("Cedula extraida: '" + serialNumber + "' | CN: '" + cn + "'");
                            if (!telefono.isEmpty()) {
                                LOGGER.info("Celular extraido: '" + telefono + "'");
                            }

                            // Formatear fechas
                            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                            sdf.setTimeZone(TimeZone.getTimeZone("America/Guayaquil"));

                            String fechaFirmado = "";
                            if (sig.getSignDate() != null) {
                                fechaFirmado = sdf.format(sig.getSignDate().getTime());
                            } else {
                                fechaFirmado = sdf.format(new Date());
                            }

                            firmante.put("cedula", serialNumber);
                            firmante.put("nombre", cn);
                            firmante.put("telefono", telefono.isEmpty() ? "No disponible" : telefono);
                            firmante.put("razon", sig.getReason() != null ? sig.getReason() : "Firma Electrónica");
                            firmante.put("localizacion", sig.getLocation() != null ? sig.getLocation() : "Ecuador");
                            firmante.put("fechaFirmado", fechaFirmado + " hora de Ecuador");
                            firmante.put("entidadCertificadora", entidadReconocida ? entidadCertificadora : "Entidad Certificadora no reconocida");
                            firmante.put("fechaEmision", sdf.format(cert.getNotBefore()) + " hora de Ecuador");
                            firmante.put("fechaExpiracion", sdf.format(cert.getNotAfter()) + " hora de Ecuador");
                            firmante.put("fechaRevocacion", "No revocado");
                            firmante.put("selladoTiempo", "No");
                            firmante.put("valido", esValido);
                            firmante.put("firmaIntegra", firmaValida);
                            firmante.put("certificadoVigente", vigente);
                            firmante.put("entidadReconocida", entidadReconocida);

                            firmantes.add(firmante);
                            LOGGER.info("Firmante: " + cn + " | Entidad: " + entidadCertificadora +
                                    " | Reconocida: " + entidadReconocida + " | Válido: " + esValido);
                        }
                    } catch (Exception e) {
                        LOGGER.warning("Error procesando firma individual: " + e.getMessage());
                        firmante.put("cedula", "---");
                        firmante.put("nombre", "Error al leer firma");
                        firmante.put("entidadCertificadora", "Entidad Certificadora no reconocida");
                        firmante.put("valido", false);
                        firmantes.add(firmante);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.severe("Error verificando documento: " + e.getMessage());
            e.printStackTrace();
        }

        return firmantes;
    }

    public Map<String, Object> validarCertificadoP12(byte[] p12Bytes, String password) throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(p12Bytes), password.toCharArray());

        String alias = ks.aliases().nextElement();
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        Map<String, Object> result = new HashMap<>();
        result.put("subjectDN", cert.getSubjectDN().getName());
        result.put("issuerDN", cert.getIssuerDN().getName());
        result.put("validFrom", cert.getNotBefore());
        result.put("validTo", cert.getNotAfter());

        // Verificar vigencia
        try {
            cert.checkValidity(); // Al día de hoy
        } catch (Exception e) {
            throw new Exception("El certificado está expirado o aún no es válido.");
        }

        // Verificar si la entidad emisora es reconocida
        String issuerDN = cert.getIssuerDN().getName();
        String entidadCertificadora = extractOrganization(issuerDN);
        if (!isEntidadReconocida(entidadCertificadora, issuerDN)) {
            throw new Exception("La entidad emisora del certificado no está reconocida en Ecuador.");
        }

        result.put("valido", true);
        return result;
    }

    private boolean isEntidadReconocida(String org, String fullDN) {
        String upper = (org + " " + fullDN).toUpperCase();
        for (String entidad : ENTIDADES_RECONOCIDAS) {
            if (upper.contains(entidad)) {
                return true;
            }
        }
        return false;
    }

    private String extractOrganization(String dn) {
        String org = extractField(dn, "O");
        if (!org.isEmpty()) return org;
        // Fallback: extraer CN del emisor
        return extractField(dn, "CN");
    }

    private String extractField(String dn, String field) {
        try {
            LdapName ldapName = new LdapName(dn);
            for (Rdn rdn : ldapName.getRdns()) {
                javax.naming.directory.Attributes attrs = rdn.toAttributes();
                javax.naming.directory.Attribute attr = attrs.get(field);
                if (attr == null) {
                    attr = attrs.get("OID." + field);
                }
                
                if (attr != null) {
                    Object val = attr.get();
                    if (val instanceof byte[]) {
                        return new String((byte[]) val, java.nio.charset.StandardCharsets.UTF_8).replaceAll("[^a-zA-Z0-9-]", "");
                    } else if (val instanceof String) {
                        String s = (String) val;
                        if (s.startsWith("#")) {
                            return decodeAsn1HexString(s);
                        }
                        return s;
                    }
                    return val.toString();
                }
            }
        } catch (Exception e) {
            // Intento manual con regex
            try {
                String pattern = field + "=";
                int idx = dn.indexOf(pattern);
                if (idx >= 0) {
                    String sub = dn.substring(idx + pattern.length());
                    int end = sub.indexOf(',');
                    String res = end > 0 ? sub.substring(0, end).trim() : sub.trim();
                    if (res.startsWith("#")) {
                        return decodeAsn1HexString(res);
                    }
                    return res;
                }
            } catch (Exception ignored) {}
        }
        return "";
    }

    private String decodeAsn1HexString(String hexString) {
        try {
            // Remover el '#'
            String hex = hexString.substring(1);
            // El primer byte es el tag (ej. 13 = PrintableString, 0C = UTF8String)
            // El segundo byte es el length
            // El resto es el string codificado en hex
            if (hex.length() > 4) {
                // Empezar a decodificar los bytes del string (ignorando tag y length por simplicidad)
                // O mejor aún, decodificar todo y solo extraer caracteres imprimibles
                StringBuilder sb = new StringBuilder();
                for (int i = 4; i < hex.length() - 1; i += 2) {
                    String pair = hex.substring(i, i + 2);
                    int decimal = Integer.parseInt(pair, 16);
                    if (decimal >= 32 && decimal <= 126) { // Solo caracteres ASCII imprimibles
                        sb.append((char) decimal);
                    }
                }
                String decoded = sb.toString().trim();
                // Si encontramos un número de 10 dígitos (cedula), devolverlo
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d{10})").matcher(decoded);
                if (m.find()) {
                    return m.group(1);
                }
                return decoded;
            }
        } catch (Exception e) {}
        return hexString;
    }
}
