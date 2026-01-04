# Community Contribution TODOs for APIForge Open Core

This document outlines specific, actionable tasks suitable for open-source community contributions to the APIForge open-core project. Contributions in these areas will significantly enhance the project's functionality, quality, and developer experience.

## 1. API Generation & Framework Support (Highest Priority)

-   [ ] **Validate and Harden Java/Spring API Generation:**
    -   **Context:** The current API generator relies on a generic AI prompt. The generated code for Java/Spring is likely to be incomplete or have issues with build files (`pom.xml`) and dependency management.
    -   **Task:**
        1.  Generate several Java/Spring projects using the APIForge generator and manually review the code for correctness and completeness.
        2.  Identify common failure patterns (e.g., incorrect dependencies, missing configurations).
        3.  Implement framework-specific post-processing logic within `packages/core/lib/build/api-generator.ts` to automatically correct these issues, or enhance the AI prompt with more specific instructions for Java/Spring.
        4.  Update the test generation logic in `packages/core/lib/build/pentestforge.ts` to produce functional JUnit tests, replacing the current placeholder (`assertThat(true).isTrue()`).

-   [ ] **Validate and Harden C#/ASP.NET API Generation:**
    -   **Context:** Similar to Java, the generated C#/ASP.NET code likely suffers from incomplete project files (`.csproj`), dependency issues, and other boilerplate problems.
    -   **Task:**
        1.  Perform manual review of generated C#/ASP.NET projects from the APIForge generator.
        2.  Identify and document common generation errors.
        3.  Implement post-processing logic or AI prompt enhancements in `packages/core/lib/build/api-generator.ts` to fix these errors.
        4.  Update the test generation logic in `packages/core/lib/build/pentestforge.ts` to produce functional xUnit tests, replacing the current placeholder (`Assert.True(true);`).

## 2. Other Feature Implementation (Open Core)
-   [ ] **Integrate Hugging Face for Local AI Inference:**
    -   **File:** `packages/core/lib/hybrid-ai.ts`
    -   **Task:** Replace the mock `callMLProvider` function with a real implementation that integrates with the Hugging Face Transformers library, allowing for self-hosted AI model inference within the open-core.
-   [ ] **Enhance Open-Core Security Scanning:**
    -   **File:** `packages/core/lib/build/secureforge.ts`
    -   **Task:** Implement a non-AI static analysis engine within the `detectSecrets` or a new function. This involves adding a comprehensive library of regex patterns to detect common vulnerabilities (e.g., SQL Injection, Cross-Site Scripting, insecure configurations) to provide robust security scanning for the free tier without relying on premium AI models.

## 3. SDK Development (New Repositories)

-   [ ] **Create Python SDK:** Develop a Python-native SDK (`apiforge-python`) with a client class and middleware for popular frameworks like **Flask** and **FastAPI**, enabling Python developers to easily integrate with APIForge.
-   [ ] **Create Go SDK:** Develop an idiomatic Go SDK (`go-apiforge`) with a client and middleware for standard libraries like `net/http` and frameworks such as **Gin**, to support Go-based projects.
-   [ ] **Create Java SDK:** Develop a Java SDK (`apiforge-java`) with a client (e.g., using OkHttp/Retrofit) and integrations for frameworks like **Spring Boot**, for Java-centric applications.
-   [ ] **Create Ruby SDK:** Develop a Ruby Gem (`apiforge-ruby`) with a client and middleware for **Ruby on Rails** and Rack, extending APIForge's reach to the Ruby ecosystem.
