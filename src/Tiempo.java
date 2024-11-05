public class Tiempo {
    private long tiempo_inicio;



    public Tiempo(){
        this.tiempo_inicio = System.nanoTime();
    }

    public long getTiempo(){
        long resp = Math.abs(System.nanoTime()-this.tiempo_inicio) /1000000;
        return resp;
    }
    public double getTiempoNs(){
        return ((double) System.nanoTime()- (double)this.tiempo_inicio)/1000000;
    }
}
