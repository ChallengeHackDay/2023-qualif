import { Fragment, useEffect, useState } from "react"
import Footer from "../components/footer"
import Header from "../components/header"
import  { Prism as SyntaxHighlighter } from "react-syntax-highlighter"
import { coldarkDark } from "react-syntax-highlighter/dist/esm/styles/prism"
import { Alert, AlertColor, Button, Typography } from "@mui/material"
import { LoadingButton } from "@mui/lab"
import { serverAddress } from "../../config.json"

type Props = {
    name: string
    description: string,
    checkable: boolean,
    contracts: string[]
}

type CheckResult = {
    locked: boolean,
    flag: string | undefined
}

async function deploy(name: string, setAddress: (address: string | undefined) => void) {
    try {
        const resp = await fetch(serverAddress + "/deploy", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ contractName: name }),
            credentials: "include"
        })

        if (resp.ok) {
            const { address } = await resp.json()
            setAddress(address)
        }
        else {
            setAddress(undefined)
        }
    }
    catch {
        setAddress(undefined)
    }
}

async function check(name: string, setCheckResult: (result: CheckResult | null | undefined) => void) {
    try {
        const resp = await fetch(serverAddress + "/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ contractName: name }),
            credentials: "include"
        })

        if (resp.ok) {
            const result = (await resp.json()) as CheckResult

            setCheckResult(result)
        }
        else {
            setCheckResult(null)
        }
    }
    catch {
        setCheckResult(null)
    }

    window.scrollTo({ top: 0, behavior: "smooth" })
}

export default function Challenge({ name, description, checkable, contracts }: Props) {
    const [address, setAddress] = useState<string | undefined>()

    const [checkResult, setCheckResult] = useState<CheckResult | null | undefined>()
    const [deploying, setDeploying] = useState(false)

    useEffect(() => {
        setAddress(undefined)
        setCheckResult(undefined)
    }, [name, description, contracts])

    let alertContent = "Sorry, an error occured while checking the contract."
    let alertSeverity = "error"

    if (checkResult) {
        if (checkResult.locked) {
            alertContent = "Oh oh! You didn't complete the challenge yet."
        }
        else {
            alertContent = checkResult.flag as string
            alertSeverity = "success"
        }
    }

    return (<>
        <Header/>
            <Typography sx={{ width: "fit-content", mx: "auto", "mt": "30px" }} component="div">
                {checkResult !== undefined && <Alert onClose={alertSeverity === "error" ? (() => setCheckResult(undefined)) : undefined} severity={alertSeverity as AlertColor}>{alertContent}</Alert>}
            </Typography>
            <Typography sx={{ textAlign: "center", mt: "50px", fontSize: 40 }}>
                {name}
            </Typography>
            <Typography sx={{ textAlign: "center", my: "50px", width: 1100, mx: "auto" }}>
                {description.split("\n").map((line, i) => <Fragment key={i}>{line}<br/></Fragment>)}
            </Typography>
            {contracts.map(contract => (<SyntaxHighlighter language="solidity" style={coldarkDark} className="codeBlock">
                {contract}
            </SyntaxHighlighter>))}
            <Typography sx={{ bgcolor: "#16181C", color: "white", width: 800, px: "15px", py: "10px", m: "auto", borderRadius: "10px" }}>
                {address ? `Contract deployed at ${address}` : "Not deployed yet"}
            </Typography>
            <Typography sx={{ width: 800, m: "auto", mt: "50px", pb: "50px", display: "flex", justifyContent: "space-around" }}>
                <LoadingButton loading={deploying} variant="contained" disabled={address !== undefined} onClick={async () => {
                    setDeploying(true)
                    await deploy(name, setAddress)
                    setDeploying(false)
                }}>
                    Deploy
                </LoadingButton>
                {checkable && <Button variant="contained" onClick={() => checkResult !== undefined && checkResult !== null && !checkResult.locked ? window.scrollTo({ top: 0, behavior: "smooth" }) : check(name, setCheckResult)} disabled={!address}>
                    Check
                </Button>}
            </Typography>
        <Footer/>
    </>)
}