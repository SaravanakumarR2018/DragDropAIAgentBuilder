import ReactDOM from "react-dom/client";
import reportWebVitals from "./reportWebVitals";

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./App.css";
import "./style/applies.css";

// @ts-ignore


import CustomApp from "./customization/custom-App";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(<CustomApp />);
reportWebVitals();
