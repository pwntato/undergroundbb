import React, { useEffect } from "react";
import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";
import Container from "@mui/material/Container";
import AppRoutes from "./Routes";
import theme from "./theme";
import { useUser } from "./contexts/UserContext";
import { getCurrentUser } from "./api/userAPI";
import ErrorBoundary from "./ErrorBoundary";

function App() {
  const { state, dispatch } = useUser();

  useEffect(() => {
    const fetchCurrentUser = async () => {
      try {
        const user = await getCurrentUser();
        if (user) {
          dispatch({ type: "LOGIN", payload: { username: user.username } });
          dispatch({ type: "SET_GROUPS", payload: user.groups });
        }
      } catch (error) {
        console.error("Error fetching current user", error);
      }
    };

    fetchCurrentUser();
  }, [dispatch]);

  useEffect(() => {
    if (state.selectedGroup && state.selectedGroup.name) {
      document.title = `${state.selectedGroup.name} - UndergroundBB.net`;
    } else {
      document.title = "UndergroundBB.net";
    }
  }, [state.selectedGroup]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container sx={{ paddingLeft: 1, paddingRight: 1, paddingBottom: 2 }}>
        <ErrorBoundary>
          <AppRoutes />
        </ErrorBoundary>
      </Container>
    </ThemeProvider>
  );
}

export default App;
