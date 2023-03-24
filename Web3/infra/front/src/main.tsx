import "@fontsource/roboto/300.css"
import "@fontsource/roboto/400.css"
import "@fontsource/roboto/500.css"
import "@fontsource/roboto/700.css"
import { StrictMode } from "react"
import ReactDOM from "react-dom/client"
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"
import App from "./App"
import Faucet from "./routes/faucet"
import Challenge from "./routes/challenge"
import NotFound from "./routes/404"
import { Disclosure } from "./contracts/Disclosure"
import { Diamond } from "./contracts/Diamond"
import { Gate } from "./contracts/Gate"
import "./globals.css"

export const challenges = [Gate, Disclosure, Diamond]

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <StrictMode>
        <App>
            <BrowserRouter>
                <Routes>
                    <Route path="/" element={<Navigate to="/gate"/>}/>
                    {challenges.map((challenge) => (
                        <Route path={`/${challenge.name.toLowerCase()}`} key={challenge.name} element={
                            <Challenge name={challenge.name}
                            description={challenge.description}
                            checkable={challenge.checkable}
                            contracts={challenge.contracts}/>
                        }/>
                    ))}
                    <Route path="/faucet" element={<Faucet/>}/>
                    <Route path="*" element={<NotFound/>}/>
                </Routes>
            </BrowserRouter>
        </App>
    </StrictMode>
)