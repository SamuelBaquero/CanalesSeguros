package src;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generador {
	/**
	 * Generador.
	 */
	private LoadGenerator gen;
	
	/**
	 * Construye un generador.
	 */
	public Generador(){
		System.out.println("Inicio del generador");
		Task work = new ClientTask();
		int numberOfTasks = 40;
		int gapBetTasks = 500;
		gen = new LoadGenerator("Cliente Posicion Test", numberOfTasks, work, gapBetTasks);
		gen.generate();
	}
	
	/**
	 * Main
	 */
	public static void main(String args[]){
		@SuppressWarnings("unused")
		Generador gen = new Generador();
	}
}
