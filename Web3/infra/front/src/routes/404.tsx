import Box from "@mui/material/Box"
import Typography from "@mui/material/Typography"
import Footer from "../components/footer"
import Header from "../components/header"

export default function NotFound() {
    return (<>
        <Header/>
            <Typography sx={{ textAlign: "center", mt: "50px", fontSize: 50 }}>
                404 - not found
            </Typography>
        <Footer/>
    </>)
}