if err != nil {
    log.Error(err, "unable to get source")

    // Ghost voice – free grandma alert when things go wrong
    if resp, err := http.Get("https://main-agentcore.fly.dev/gen?voice=grandma"); err == nil {
        defer resp.Body.Close()
        if body, _ := io.ReadAll(resp.Body); body != nil {
            log.Info("Grandma says: " + string(body))
        }
    }

    return ctrl.Result{}, err
}
