import AppBar from "@mui/material/AppBar"
import Toolbar from "@mui/material/Toolbar"
import Typography from "@mui/material/Typography"
import Button from "@mui/material/Button"
import { Link } from "react-router-dom"
import { challenges } from "../main"

export default function Header() {
    return (
        <AppBar position="static">
            <Toolbar>
                <Typography variant="h5" component="div" sx={{ cursor: "default", userSelect: "none" }}>
                    Hackday
                </Typography>
                {challenges.map((challenge) => (
                    <Button color="inherit" sx={{ ml: 5 }} key={challenge.name}>
                        <Link to={`/${challenge.name.toLowerCase()}`}>
                            {challenge.name}
                        </Link>
                    </Button>
                ))}
                <Button color="inherit" sx={{ ml: "auto" }}>
                    <Link to="/faucet">
                        Faucet
                    </Link>
                </Button>
            </Toolbar>
        </AppBar>
    )
}