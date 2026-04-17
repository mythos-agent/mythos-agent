export interface Preset {
  name: string;
  description: string;
  config: {
    scan: {
      include: string[];
      exclude: string[];
    };
  };
}

export const PRESETS: Record<string, Preset> = {
  express: {
    name: "Express.js",
    description: "Node.js + Express API server",
    config: {
      scan: {
        include: ["**/*.ts", "**/*.js", "**/*.json"],
        exclude: [
          "node_modules/**",
          "dist/**",
          "build/**",
          ".git/**",
          ".sphinx/**",
          "**/*.test.*",
          "**/*.spec.*",
          "coverage/**",
        ],
      },
    },
  },
  nextjs: {
    name: "Next.js",
    description: "Next.js full-stack application",
    config: {
      scan: {
        include: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
        exclude: [
          "node_modules/**",
          ".next/**",
          "out/**",
          ".git/**",
          ".sphinx/**",
          "**/*.test.*",
          "**/*.spec.*",
          "public/**",
        ],
      },
    },
  },
  django: {
    name: "Django",
    description: "Python Django web application",
    config: {
      scan: {
        include: ["**/*.py", "**/*.html", "**/*.yml", "**/*.yaml"],
        exclude: [
          "venv/**",
          ".venv/**",
          "__pycache__/**",
          "*.pyc",
          ".git/**",
          ".sphinx/**",
          "migrations/**",
          "static/**",
        ],
      },
    },
  },
  flask: {
    name: "Flask",
    description: "Python Flask API/web application",
    config: {
      scan: {
        include: ["**/*.py", "**/*.html", "**/*.yml"],
        exclude: ["venv/**", ".venv/**", "__pycache__/**", ".git/**", ".sphinx/**"],
      },
    },
  },
  spring: {
    name: "Spring Boot",
    description: "Java Spring Boot application",
    config: {
      scan: {
        include: ["**/*.java", "**/*.xml", "**/*.yml", "**/*.yaml", "**/*.properties"],
        exclude: ["target/**", "build/**", ".gradle/**", ".git/**", ".sphinx/**", "**/test/**"],
      },
    },
  },
  go: {
    name: "Go",
    description: "Go web service / API",
    config: {
      scan: {
        include: ["**/*.go", "**/*.yml", "**/*.yaml"],
        exclude: ["vendor/**", ".git/**", ".sphinx/**", "**/*_test.go"],
      },
    },
  },
  react: {
    name: "React",
    description: "React frontend application",
    config: {
      scan: {
        include: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
        exclude: [
          "node_modules/**",
          "build/**",
          "dist/**",
          ".git/**",
          ".sphinx/**",
          "**/*.test.*",
          "**/*.spec.*",
          "public/**",
        ],
      },
    },
  },
  fullstack: {
    name: "Full Stack",
    description: "Monorepo with frontend + backend + infrastructure",
    config: {
      scan: {
        include: [
          "**/*.ts",
          "**/*.tsx",
          "**/*.js",
          "**/*.jsx",
          "**/*.py",
          "**/*.go",
          "**/*.java",
          "**/*.php",
          "**/*.yml",
          "**/*.yaml",
          "**/Dockerfile*",
          "**/*.tf",
        ],
        exclude: [
          "node_modules/**",
          "dist/**",
          "build/**",
          ".git/**",
          ".sphinx/**",
          "vendor/**",
          "venv/**",
          "__pycache__/**",
          "target/**",
          "**/*.test.*",
          "**/*.spec.*",
          "**/*.min.js",
        ],
      },
    },
  },
};

export function getPresetNames(): string[] {
  return Object.keys(PRESETS);
}

export function getPreset(name: string): Preset | null {
  return PRESETS[name] || null;
}
