import { createTheme, ThemeProvider } from "@mui/material/styles"
import { CssBaseline } from "@mui/material"

export default function App({ children }: { children: React.ReactNode }) {    
    const theme = createTheme({ palette: { mode: "dark" } })
    
    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            {children}
        </ThemeProvider>
    )
}