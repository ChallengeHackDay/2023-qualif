import { useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import "./App.css";

function App() {
  const [result, setResult] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  async function check() {
    try {
      const res: string = await invoke("check", { username: username, password });
      setResult(res);
    }
    catch (e: any) {
      setResult(e.message);
    }
  }

  return (
    <div className="container">
      <video autoPlay muted loop id="videoBackground">
        <source src="./background.mp4" type="video/mp4"/>
      </video>

      <h1>Taurus ACS v1.0</h1>

      <p>You must log in to access the operator dashboard.</p>

      <div className="row">
        <div>
        <input
            id="greet-input"
            onChange={(e) => setUsername(e.currentTarget.value)}
            placeholder="Enter a name..."
          /><br/>
          <input
            id="greet-input"
            type="password"
            onChange={(e) => setPassword(e.currentTarget.value)}
            placeholder="Enter a password..."
          /><br/>
          <button type="button" onClick={() => check()}>
            Log in
          </button>
        </div>
      </div>
      <p id="result">{result}</p>
    </div>
  );
}

export default App;
