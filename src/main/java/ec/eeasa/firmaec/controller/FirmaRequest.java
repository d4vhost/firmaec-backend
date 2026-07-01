package ec.eeasa.firmaec.controller;

public class FirmaRequest {
    private String pdfBase64;
    private String p12Base64;
    private String password;
    private int pagina;
    private float posX;
    private float posY;

    // Getters y Setters
    public String getPdfBase64() {
        return pdfBase64;
    }

    public void setPdfBase64(String pdfBase64) {
        this.pdfBase64 = pdfBase64;
    }

    public String getP12Base64() {
        return p12Base64;
    }

    public void setP12Base64(String p12Base64) {
        this.p12Base64 = p12Base64;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getPagina() {
        return pagina;
    }

    public void setPagina(int pagina) {
        this.pagina = pagina;
    }

    public float getPosX() {
        return posX;
    }

    public void setPosX(float posX) {
        this.posX = posX;
    }

    public float getPosY() {
        return posY;
    }

    public void setPosY(float posY) {
        this.posY = posY;
    }
}
