package sniffer;

import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception {
		PcapIf device = null;

		FXMLLoader fxmlLoaderInterface = new FXMLLoader(getClass().getResource("interface.fxml"));
		FXMLLoader fxmlLoaderMain = new FXMLLoader(getClass().getResource("Main.fxml"));
		Parent interfaces = fxmlLoaderInterface.load();
		Parent main = fxmlLoaderMain.load();
		ControllerInterface CtrlInterf = fxmlLoaderInterface.getController();

		device = CtrlInterf.getInterface();

		primaryStage.setTitle("Sniffer");
		// primaryStage.setScene(new Scene(interfaces));
		primaryStage.setScene(new Scene(main)); // 加载main布局到stage里去
		primaryStage.show();
	}

	public static void main(String[] args) {
		launch(args);
	}
}
