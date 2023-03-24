import TextField from "@mui/material/TextField"
import Alert from "@mui/material/Alert"
import Typography from "@mui/material/Typography"
import { LoadingButton } from "@mui/lab"
import Footer from "../components/footer"
import Header from "../components/header"
import { useState } from "react"
import { serverAddress } from "../../config.json"

type FaucetResult = { result: string }
enum FaucetStatus {
    OK = "OK",
    UNCHANGED = "UNCHANGED",
    FORMAT_ERROR = "FORMAT_ERROR",
    TRANSACTION_FAILED = "TRANSACTION_FAILED",
    NETWORK_ERROR = "NETWORK_ERROR",
    CHAIN_NOT_AVAILABLE = "CHAIN_NOT_AVAILABLE",
    PENDING = "PENDING",
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
}

async function submitHandler(address: string, setStatus: (result: FaucetStatus | undefined) => void) {
    try {
        const rep = await fetch(serverAddress + "/faucet", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ address }),
        })

        if (rep.ok) {
            const { result }: FaucetResult = await rep.json()

            if ([FaucetStatus.OK, FaucetStatus.UNCHANGED, FaucetStatus.CHAIN_NOT_AVAILABLE, FaucetStatus.TRANSACTION_FAILED, FaucetStatus.PENDING].includes(result as FaucetStatus)) {
                setStatus(result as FaucetStatus)
            }
            else {
                setStatus(FaucetStatus.FORMAT_ERROR)
            }
        }
        else {
            setStatus(FaucetStatus.UNKNOWN_ERROR)
        }
    }
    catch {
        setStatus(FaucetStatus.NETWORK_ERROR)
    }
}

export default function Faucet() {
    const [address, setAddress] = useState("")
    const [pending, setPending] = useState(false)
    const [status, setStatus] = useState<FaucetStatus | undefined>()

    return (<>
        <Header/>
            <Typography sx={{ textAlign: "center", mt: "50px" }} component="div">
            {status && <Alert sx={{ width: "fit-content", mx: "auto" }} severity={status === FaucetStatus.OK ? "success" : (status === FaucetStatus.UNCHANGED ? "info" : "error")}>
                    {status === FaucetStatus.OK && "Check your wallet, you should have received 5 ESI!"}
                    {status === FaucetStatus.UNCHANGED && "You already have at least 5 ESI in your wallet!"}
                    {status === FaucetStatus.CHAIN_NOT_AVAILABLE && "The blockchain couldn't be reached. If it persists, please report this issue to the organizers."}
                    {status === FaucetStatus.PENDING && "You already have a pending transaction. Please wait for it to be processed."}
                    {status === FaucetStatus.FORMAT_ERROR && "The server answered with something unexpected. This isn't supposed to happen, please report this issue to the organizers."}
                    {status === FaucetStatus.TRANSACTION_FAILED && "The transaction failed. Check that your address is valid."}
                    {status === FaucetStatus.NETWORK_ERROR && "A network error occured. Please check your internet connection and try again."}
                    {status === FaucetStatus.UNKNOWN_ERROR && "Some unknown error occured."}
                </Alert>}
                <br/>
                <Typography sx={{mb: "1em", fontSize: "2em"}}>Official outpost faucet</Typography>
                <Typography sx={{my: "1em"}}>To help you get started with the blockchain ecosystem we have set up in our outpost, you can request 5 ESI here if your balance is less than this amount.</Typography>
                <Typography sx={{my: "1em", mb: "3em"}}>Useful note: this faucet is also the account used to deploy the contracts.</Typography>

                <Typography sx={{my: "1em", mt: "3em"}}>Please enter your address here:</Typography>
                <TextField id="outlined-basic" label="Account address" variant="outlined" sx={{ width: "500px", backgroundColor: "#00000055" }} value={address} onChange={e => setAddress(e.target.value)} autoComplete={"off"} /><br/>
                <LoadingButton loading={pending} variant="contained" disabled={address.length === 0} sx={{ mt: "30px" }} onClick={async () => {
                    setPending(true)
                    await submitHandler(address, setStatus)
                    setPending(false)
                }}>
                    GET THE MONEY
                </LoadingButton>
            </Typography>
        <Footer/>
    </>)
}