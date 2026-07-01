package ec.eeasa.firmaec.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.imageio.ImageIO;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

@Service
public class FirmaECService {

    private static final Logger LOGGER = Logger.getLogger(FirmaECService.class.getName());

    public String firmarDocumento(String pdfBase64, String p12Base64, String password, int pagina, float posX, float posY) {
        LOGGER.info("Iniciando firma. Coordenadas -> pagina=" + pagina + " posX=" + posX + " posY=" + posY);
        
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            byte[] pdfBytes = Base64.getDecoder().decode(pdfBase64);
            byte[] p12Bytes = Base64.getDecoder().decode(p12Base64);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(p12Bytes), password.toCharArray());

            Enumeration<String> aliases = keystore.aliases();
            String alias = null;
            while (aliases.hasMoreElements()) {
                alias = aliases.nextElement();
                if (keystore.isKeyEntry(alias)) break;
            }
            if (alias == null) throw new RuntimeException("No se encontro llave privada en el certificado.");

            PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
            Certificate[] certChain = keystore.getCertificateChain(alias);
            X509Certificate x509Cert = (X509Certificate) certChain[0];
            String signerName = extractCommonName(x509Cert.getSubjectX500Principal().getName());

            // ============================================================
            // PASO 1: Dibujar el sello visual (QR + texto) y guardar FULL
            // ============================================================
            byte[] pdfConSello = dibujarSelloVisual(pdfBytes, pagina, posX, posY, signerName);
            LOGGER.info("PASO 1 completado: sello visual dibujado. PDF size=" + pdfConSello.length);

            // ============================================================
            // PASO 2: Recargar el PDF con sello y aplicar firma digital
            // ============================================================
            byte[] pdfFirmado = aplicarFirmaDigital(pdfConSello, privateKey, certChain, signerName);
            LOGGER.info("PASO 2 completado: firma digital aplicada. PDF size=" + pdfFirmado.length);

            return Base64.getEncoder().encodeToString(pdfFirmado);

        } catch (Exception e) {
            LOGGER.severe("Error al firmar: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error en la firma electronica", e);
        }
    }

    /**
     * PASO 1: Dibuja el QR y el texto en el PDF y lo guarda completamente (save full).
     */
    private byte[] dibujarSelloVisual(byte[] pdfBytes, int pagina, float posX, float posY, String signerName) throws Exception {
        // Generar QR como archivo temporal PNG
        File tempQR = File.createTempFile("qr_firma_", ".png");
        try {
            generateQRCodeToFile("https://www.firmadigital.gob.ec/validador/", tempQR);
            LOGGER.info("QR temporal creado: " + tempQR.getAbsolutePath() + " (" + tempQR.length() + " bytes)");

            try (PDDocument document = PDDocument.load(pdfBytes)) {
                int targetPage = (pagina > 0 && pagina <= document.getNumberOfPages()) ? (pagina - 1) : 0;
                PDPage pdPage = document.getPage(targetPage);

                PDImageXObject pdImage = PDImageXObject.createFromFile(tempQR.getAbsolutePath(), document);
                LOGGER.info("PDImageXObject creado: " + pdImage.getWidth() + "x" + pdImage.getHeight());

                if (posX <= 0 && posY <= 0) {
                    posX = 50;
                    posY = 50;
                }

                // Dividir nombre en dos lineas
                String[] nameParts = signerName.toUpperCase().split("\\s+");
                String nameLine1 = signerName.toUpperCase();
                String nameLine2 = "";
                if (nameParts.length > 2) {
                    int mid = nameParts.length / 2;
                    nameLine1 = String.join(" ", Arrays.copyOfRange(nameParts, 0, mid + (nameParts.length % 2)));
                    nameLine2 = String.join(" ", Arrays.copyOfRange(nameParts, mid + (nameParts.length % 2), nameParts.length));
                } else if (nameParts.length == 2) {
                    nameLine1 = nameParts[0];
                    nameLine2 = nameParts[1];
                }

                try (PDPageContentStream cs = new PDPageContentStream(document, pdPage, PDPageContentStream.AppendMode.APPEND, true, true)) {
                    float qrSize = 55f;
                    cs.drawImage(pdImage, posX, posY, qrSize, qrSize);
                    LOGGER.info("QR dibujado en x=" + posX + " y=" + posY);

                    // Texto pegado al QR (3pt de separacion, alineado al borde superior)
                    float textX = posX + qrSize + 3;
                    float textY = posY + qrSize - 7;

                    cs.beginText();
                    cs.setFont(PDType1Font.COURIER, 6);
                    cs.newLineAtOffset(textX, textY);
                    cs.showText("Validar unicamente en FirmaEC.");
                    cs.newLineAtOffset(0, -8);
                    cs.showText("Firmado electronicamente por:");
                    cs.setFont(PDType1Font.COURIER_BOLD, 8);
                    cs.newLineAtOffset(0, -10);
                    cs.showText(nameLine1);
                    if (!nameLine2.isEmpty()) {
                        cs.newLineAtOffset(0, -9);
                        cs.showText(nameLine2);
                    }
                    cs.endText();
                }

                // GUARDAR COMPLETAMENTE (no incremental) para que la imagen QR quede persistida
                ByteArrayOutputStream fullSave = new ByteArrayOutputStream();
                document.save(fullSave);
                return fullSave.toByteArray();
            }
        } finally {
            tempQR.delete();
        }
    }

    /**
     * PASO 2: Aplica la firma criptografica al PDF que ya tiene el sello visual.
     */
    private byte[] aplicarFirmaDigital(byte[] pdfConSello, PrivateKey privateKey, Certificate[] certChain, String signerName) throws Exception {
        try (PDDocument document = PDDocument.load(pdfConSello)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setName(signerName);
            signature.setLocation("Ecuador");
            signature.setReason("Firma Electronica");
            signature.setSignDate(Calendar.getInstance());

            document.addSignature(signature, new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws IOException {
                    try {
                        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
                        X509Certificate cert = (X509Certificate) certChain[0];
                        ContentSigner shaSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
                        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().build()).build(shaSigner, cert));
                        gen.addCertificates(new JcaCertStore(Arrays.asList(certChain)));
                        byte[] contentBytes = org.apache.pdfbox.io.IOUtils.toByteArray(content);
                        CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(contentBytes), false);
                        return signedData.getEncoded();
                    } catch (Exception e) {
                        throw new IOException("Error generando firma CMS", e);
                    }
                }
            });

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.saveIncremental(baos);
            return baos.toByteArray();
        }
    }

    private String extractCommonName(String principalName) {
        try {
            LdapName ldapDN = new LdapName(principalName);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            LOGGER.warning("No se pudo parsear el CN.");
        }
        return principalName;
    }

    private void generateQRCodeToFile(String text, File outputFile) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, 1);

        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, 300, 300, hints);
        int w = bitMatrix.getWidth();
        int h = bitMatrix.getHeight();

        // TYPE_INT_ARGB = fondo TRANSPARENTE (solo los modulos negros son visibles)
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        // NO pintar fondo blanco -> queda transparente
        g.setColor(Color.BLACK);
        for (int x = 0; x < w; x++) {
            for (int y = 0; y < h; y++) {
                if (bitMatrix.get(x, y)) g.fillRect(x, y, 1, 1);
            }
        }
        g.dispose();

        ImageIO.write(image, "PNG", outputFile);
        LOGGER.info("QR PNG transparente: " + outputFile.getAbsolutePath() + " -> " + outputFile.length() + " bytes");
    }
}
