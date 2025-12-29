--[[
  Resource Manager v4.1 - Fixed Edition
  Optimizado para estabilidad y menor detección
]]

-- === CONFIGURACIÓN MEJORADA ===
local Config = {
    Modes = {
        ["Low"] = {intensity = 25, batch = 50, delay = 0.3},
        ["Medium"] = {intensity = 50, batch = 100, delay = 0.15},
        ["High"] = {intensity = 75, batch = 200, delay = 0.08},
        ["Extreme"] = {intensity = 100, batch = 350, delay = 0.04}
    },
    SafeMemoryThreshold = 200,
    AutoStopTime = 120
}

-- === INICIALIZACIÓN SEGURA ===
local success, services = pcall(function()
    local game = game
    return {
        Players = game:GetService("Players"),
        RunService = game:GetService("RunService"),
        TweenService = game:GetService("TweenService"),
        UserInputService = game:GetService("UserInputService"),
        CoreGui = game:GetService("CoreGui"),
        ReplicatedStorage = game:GetService("ReplicatedStorage"),
        ServerStorage = game:GetService("ServerStorage"),
        ServerScriptService = game:GetService("ServerScriptService"),
        Workspace = workspace
    }
end)

if not success then
    warn("Error al cargar servicios:", services)
    return
end

local Players = services.Players
local RunService = services.RunService
local TweenService = services.TweenService
local UserInputService = services.UserInputService
local CoreGui = services.CoreGui
local ReplicatedStorage = services.ReplicatedStorage
local ServerStorage = services.ServerStorage
local ServerScriptService = services.ServerScriptService
local Workspace = services.Workspace

-- Variables esenciales
local LocalPlayer = Players.LocalPlayer
local isMobile = UserInputService.TouchEnabled
local isStudio = RunService:IsStudio()

-- === LOGGER MEJORADO ===
local Logger = {
    entries = {},
    Add = function(self, msg, level)
        level = level or "INFO"
        local entry = string.format("[%s] %s: %s", os.date("%H:%M:%S"), level, msg)
        table.insert(self.entries, entry)
        if #self.entries > 20 then table.remove(self.entries, 1) end
        if isStudio then print(entry) end
    end
}

-- === UTILIDADES ===
local function GenerateRandomName(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local name = ""
    for i = 1, (length or 12) do
        local idx = math.random(1, #chars)
        name = name .. chars:sub(idx, idx)
    end
    return name
end

-- === REMOTE SCANNER CORREGIDO ===
local RemoteScanner = {
    cache = {},
    lastScan = 0,
    
    Scan = function(self)
        local now = os.time()
        if now - self.lastScan < 10 and #self.cache > 0 then
            return self.cache
        end
        
        self.cache = {}
        local locations = {ReplicatedStorage, ServerStorage, ServerScriptService, Workspace}
        
        for _, location in ipairs(locations) do
            local success, result = pcall(function()
                local found = 0
                for _, child in ipairs(location:GetDescendants()) do
                    if child:IsA("RemoteEvent") or child:IsA("RemoteFunction") then
                        local name = child.Name:lower()
                        local safePatterns = {"update", "sync", "event", "request", "fire"}
                        local blacklist = {"kick", "ban", "admin", "mod", "report"}
                        
                        local isSafe = false
                        local isBlacklisted = false
                        
                        for _, pattern in ipairs(safePatterns) do
                            if name:find(pattern) then
                                isSafe = true
                                break
                            end
                        end
                        
                        for _, badWord in ipairs(blacklist) do
                            if name:find(badWord) then
                                isBlacklisted = true
                                break
                            end
                        end
                        
                        if isSafe and not isBlacklisted then
                            table.insert(self.cache, {
                                Object = child,
                                Type = child.ClassName,
                                Name = child.Name,
                                LastUsed = 0,
                                Score = math.random(1, 100)
                            })
                            found = found + 1
                        end
                    end
                end
                return found
            end)
            
            if not success then
                Logger:Add("Error scanning location: " .. tostring(result), "WARN")
            end
        end
        
        self.lastScan = now
        Logger:Add(string.format("Scanned %d potential remotes", #self.cache))
        return self.cache
    end,
    
    GetBestRemote = function(self)
        if #self.cache == 0 then
            self:Scan()
        end
        
        if #self.cache == 0 then
            return nil
        end
        
        table.sort(self.cache, function(a, b)
            return (a.Score or 0) < (b.Score or 0)
        end)
        
        return self.cache[1]
    end,
    
    UpdateScore = function(self, remote, increment)
        for _, r in ipairs(self.cache) do
            if r.Object == remote then
                r.Score = (r.Score or 0) + (increment or 10)
                r.LastUsed = os.time()
                break
            end
        end
    end
}

-- === LAG ENGINE CORREGIDO ===
local LagEngine = {
    active = false,
    currentMode = nil,
    threads = {},
    objects = {},
    startTime = 0,
    
    Methods = {
        SmartRemoteSpam = function(config)
            while LagEngine.active do
                local remotes = RemoteScanner.cache
                if #remotes > 0 then
                    local batchSize = math.random(1, config.batch)
                    local argsPatterns = {
                        function() return {math.random(1, 99999)} end,
                        function() return {"ping", math.random(1000, 9999)} end,
                        function() return {os.time(), "update"} end,
                        function() return {Vector3.new(math.random(), math.random(), math.random())} end,
                        function() return {CFrame.new(math.random(-100,100), math.random(0,50), math.random(-100,100))} end
                    }
                    
                    for i = 1, batchSize do
                        if not LagEngine.active then break end
                        
                        local remoteInfo = RemoteScanner:GetBestRemote()
                        if remoteInfo then
                            local success, err = pcall(function()
                                local args = argsPatterns[math.random(#argsPatterns)]()
                                
                                if remoteInfo.Type == "RemoteEvent" then
                                    remoteInfo.Object:FireServer(unpack(args))
                                elseif remoteInfo.Type == "RemoteFunction" then
                                    remoteInfo.Object:InvokeServer(unpack(args))
                                end
                                
                                RemoteScanner:UpdateScore(remoteInfo.Object)
                            end)
                            
                            if not success then
                                Logger:Add("Remote call failed: " .. tostring(err), "WARN")
                            end
                        end
                        
                        if i % 10 == 0 then
                            task.wait(0.001)
                        end
                    end
                end
                
                task.wait(config.delay * (0.8 + math.random() * 0.4))
            end
        end,
        
        PhysicsObjectCreation = function(config)
            local maxObjects = math.floor(config.intensity * 5)
            
            while LagEngine.active and #LagEngine.objects < maxObjects do
                local success, err = pcall(function()
                    local part = Instance.new("Part")
                    part.Name = GenerateRandomName(8)
                    part.Size = Vector3.new(2, 2, 2)
                    part.Position = Vector3.new(
                        math.random(-100, 100),
                        math.random(5, 30),
                        math.random(-100, 100)
                    )
                    part.Anchored = false
                    part.CanCollide = true
                    part.Material = Enum.Material.Neon
                    part.Color = Color3.fromRGB(
                        math.random(50, 255),
                        math.random(50, 255),
                        math.random(50, 255)
                    )
                    part.Transparency = 0.7
                    part.Parent = Workspace
                    
                    local force = Vector3.new(
                        math.random(-200, 200),
                        math.random(100, 300),
                        math.random(-200, 200)
                    )
                    part:ApplyImpulse(force)
                    
                    table.insert(LagEngine.objects, part)
                end)
                
                if not success then
                    Logger:Add("Physics creation failed: " .. tostring(err), "WARN")
                end
                
                task.wait(0.05 * (100 / config.intensity))
            end
        end,
        
        NetworkTrafficSimulation = function(config)
            while LagEngine.active do
                local success, err = pcall(function()
                    local remoteInfo = RemoteScanner:GetBestRemote()
                    if remoteInfo then
                        local dataSize = math.floor(config.intensity / 10)
                        local largeData = {}
                        for i = 1, dataSize do
                            largeData["key_"..i] = string.rep("X", math.random(10, 50))
                        end
                        
                        if remoteInfo.Type == "RemoteEvent" then
                            remoteInfo.Object:FireServer("data_sync", largeData, os.time())
                        end
                    end
                end)
                
                if not success then
                    Logger:Add("Network simulation failed: " .. tostring(err), "WARN")
                end
                
                task.wait(0.3 + math.random() * 0.3)
            end
        end
    },
    
    Start = function(self, modeName)
        if self.active then
            self:Stop()
            task.wait(0.5)
        end
        
        local mode = Config.Modes[modeName]
        if not mode then
            mode = Config.Modes["Medium"]
            modeName = "Medium"
        end
        
        self.active = true
        self.currentMode = modeName
        self.startTime = os.time()
        
        RemoteScanner:Scan()
        
        Logger:Add(string.format("Starting in %s mode (Intensity: %d)", modeName, mode.intensity))
        
        -- Iniciar métodos
        table.insert(self.threads, task.spawn(function()
            self.Methods.SmartRemoteSpam(mode)
        end))
        
        table.insert(self.threads, task.spawn(function()
            self.Methods.PhysicsObjectCreation(mode)
        end))
        
        table.insert(self.threads, task.spawn(function()
            self.Methods.NetworkTrafficSimulation(mode)
        end))
        
        -- Thread de limpieza
        table.insert(self.threads, task.spawn(function()
            while self.active do
                task.wait(5)
                
                -- Limpieza de objetos
                if #self.objects > 50 then
                    local toRemove = math.floor(#self.objects * 0.3)
                    for i = 1, toRemove do
                        if self.objects[i] then
                            pcall(function() self.objects[i]:Destroy() end)
                        end
                    end
                    -- Recrear tabla
                    local newObjects = {}
                    for _, obj in ipairs(self.objects) do
                        if obj and obj.Parent then
                            table.insert(newObjects, obj)
                        end
                    end
                    self.objects = newObjects
                end
                
                -- Auto-stop
                if os.time() - self.startTime > Config.AutoStopTime then
                    Logger:Add("Auto-stopping after timeout", "WARN")
                    self:Stop()
                    break
                end
            end
        end))
        
        return true
    end,
    
    Stop = function(self)
        if not self.active then return end
        
        self.active = false
        
        -- Detener threads
        for _, thread in ipairs(self.threads) do
            pcall(task.cancel, thread)
        end
        self.threads = {}
        
        -- Limpiar objetos
        for _, obj in ipairs(self.objects) do
            pcall(function() obj:Destroy() end)
        end
        self.objects = {}
        
        Logger:Add(string.format("Stopped. Runtime: %d seconds", os.time() - self.startTime))
        self.currentMode = nil
    end,
    
    GetStatus = function(self)
        return {
            Active = self.active,
            Mode = self.currentMode,
            Objects = #self.objects,
            Runtime = os.time() - self.startTime,
            Remotes = #RemoteScanner.cache
        }
    end
}

-- === INTERFAZ CORREGIDA ===
local UIController = {
    mainGUI = nil,
    floatButton = nil,
    isVisible = false,
    
    CreateMainGUI = function(self)
        -- Destruir GUI anterior si existe
        if self.mainGUI and self.mainGUI.Parent then
            self.mainGUI:Destroy()
        end
        
        local success, gui = pcall(function()
            local screenGui = Instance.new("ScreenGui")
            screenGui.Name = "RM_" .. GenerateRandomName(8)
            screenGui.Parent = CoreGui
            screenGui.ResetOnSpawn = false
            screenGui.DisplayOrder = 998
            
            -- Frame principal
            local mainFrame = Instance.new("Frame")
            mainFrame.Size = UDim2.new(0, 320, 0, 280)
            mainFrame.Position = UDim2.new(0.5, -160, 0.5, -140)
            mainFrame.BackgroundColor3 = Color3.fromRGB(35, 35, 40)
            mainFrame.BackgroundTransparency = 0.05
            mainFrame.BorderSizePixel = 0
            mainFrame.Parent = screenGui
            
            local corner = Instance.new("UICorner")
            corner.CornerRadius = UDim.new(0, 12)
            corner.Parent = mainFrame
            
            local stroke = Instance.new("UIStroke")
            stroke.Color = Color3.fromRGB(70, 70, 85)
            stroke.Thickness = 2
            stroke.Parent = mainFrame
            
            -- Header
            local header = Instance.new("Frame")
            header.Size = UDim2.new(1, 0, 0, 40)
            header.BackgroundColor3 = Color3.fromRGB(45, 45, 55)
            header.BorderSizePixel = 0
            header.Parent = mainFrame
            
            local headerCorner = Instance.new("UICorner")
            headerCorner.CornerRadius = UDim.new(0, 12)
            headerCorner.Parent = header
            
            local title = Instance.new("TextLabel")
            title.Size = UDim2.new(1, -50, 1, 0)
            title.Position = UDim2.new(0, 10, 0, 0)
            title.Text = " Resource Manager"
            title.Font = Enum.Font.GothamMedium
            title.TextSize = 16
            title.TextColor3 = Color3.fromRGB(220, 220, 240)
            title.BackgroundTransparency = 1
            title.TextXAlignment = Enum.TextXAlignment.Left
            title.Parent = header
            
            -- Minimize button
            local minButton = Instance.new("TextButton")
            minButton.Size = UDim2.new(0, 30, 0, 30)
            minButton.Position = UDim2.new(1, -35, 0.5, -15)
            minButton.AnchorPoint = Vector2.new(0.5, 0.5)
            minButton.Text = "×"
            minButton.Font = Enum.Font.GothamBold
            minButton.TextSize = 20
            minButton.TextColor3 = Color3.fromRGB(200, 200, 200)
            minButton.BackgroundTransparency = 1
            minButton.Parent = header
            
            -- Content
            local content = Instance.new("Frame")
            content.Size = UDim2.new(1, 0, 1, -40)
            content.Position = UDim2.new(0, 0, 0, 40)
            content.BackgroundTransparency = 1
            content.Parent = mainFrame
            
            -- Mode buttons
            local buttonFrame = Instance.new("Frame")
            buttonFrame.Size = UDim2.new(0.9, 0, 0, 160)
            buttonFrame.Position = UDim2.new(0.05, 0, 0.05, 0)
            buttonFrame.BackgroundTransparency = 1
            buttonFrame.Parent = content
            
            local modes = {"Low", "Medium", "High", "Extreme"}
            local colors = {
                Low = Color3.fromRGB(80, 160, 80),
                Medium = Color3.fromRGB(220, 180, 60),
                High = Color3.fromRGB(220, 120, 60),
                Extreme = Color3.fromRGB(220, 80, 80)
            }
            
            for i, mode in ipairs(modes) do
                local btn = Instance.new("TextButton")
                btn.Name = "Btn_" .. mode
                btn.Size = UDim2.new(1, 0, 0, 35)
                btn.Position = UDim2.new(0, 0, 0, (i-1)*40)
                btn.BackgroundColor3 = colors[mode]
                btn.TextColor3 = Color3.fromRGB(255, 255, 255)
                btn.Text = string.format("%s (%d%%)", mode, Config.Modes[mode].intensity)
                btn.Font = Enum.Font.GothamMedium
                btn.TextSize = 14
                btn.AutoButtonColor = false
                btn.Parent = buttonFrame
                
                local btnCorner = Instance.new("UICorner")
                btnCorner.CornerRadius = UDim.new(0, 8)
                btnCorner.Parent = btn
                
                btn.MouseButton1Click:Connect(function()
                    local status = LagEngine:GetStatus()
                    if status.Active and LagEngine.currentMode == mode then
                        LagEngine:Stop()
                        btn.BackgroundColor3 = colors[mode]
                    else
                        LagEngine:Stop()
                        task.wait(0.1)
                        LagEngine:Start(mode)
                        -- Reset other buttons
                        for _, otherMode in ipairs(modes) do
                            local otherBtn = buttonFrame:FindFirstChild("Btn_" .. otherMode)
                            if otherBtn then
                                otherBtn.BackgroundColor3 = colors[otherMode]
                                otherBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
                            end
                        end
                        -- Highlight active
                        btn.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
                        btn.TextColor3 = Color3.fromRGB(40, 40, 45)
                    end
                end)
            end
            
            -- Stop button
            local stopBtn = Instance.new("TextButton")
            stopBtn.Size = UDim2.new(0.9, 0, 0, 35)
            stopBtn.Position = UDim2.new(0.05, 0, 0.8, 0)
            stopBtn.BackgroundColor3 = Color3.fromRGB(180, 60, 80)
            stopBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
            stopBtn.Text = "STOP ALL"
            stopBtn.Font = Enum.Font.GothamBold
            stopBtn.TextSize = 14
            stopBtn.AutoButtonColor = false
            stopBtn.Parent = content
            
            local stopCorner = Instance.new("UICorner")
            stopCorner.CornerRadius = UDim.new(0, 8)
            stopCorner.Parent = stopBtn
            
            stopBtn.MouseButton1Click:Connect(function()
                LagEngine:Stop()
                for _, mode in ipairs(modes) do
                    local btn = buttonFrame:FindFirstChild("Btn_" .. mode)
                    if btn then
                        btn.BackgroundColor3 = colors[mode]
                        btn.TextColor3 = Color3.fromRGB(255, 255, 255)
                    end
                end
            end)
            
            -- Status display
            local statusFrame = Instance.new("Frame")
            statusFrame.Size = UDim2.new(0.9, 0, 0, 60)
            statusFrame.Position = UDim2.new(0.05, 0, 0.65, 0)
            statusFrame.BackgroundColor3 = Color3.fromRGB(50, 50, 60)
            statusFrame.Parent = content
            
            local statusCorner = Instance.new("UICorner")
            statusCorner.CornerRadius = UDim.new(0, 8)
            statusCorner.Parent = statusFrame
            
            local statusLabel = Instance.new("TextLabel")
            statusLabel.Size = UDim2.new(1, -10, 1, -10)
            statusLabel.Position = UDim2.new(0, 5, 0, 5)
            statusLabel.Text = "Status: Ready"
            statusLabel.Font = Enum.Font.Gotham
            statusLabel.TextSize = 12
            statusLabel.TextColor3 = Color3.fromRGB(180, 200, 220)
            statusLabel.BackgroundTransparency = 1
            statusLabel.TextWrapped = true
            statusLabel.Parent = statusFrame
            
            -- Drag system
            local dragging = false
            local dragStart, startPos
            
            header.InputBegan:Connect(function(input)
                if input.UserInputType == Enum.UserInputType.MouseButton1 or 
                   input.UserInputType == Enum.UserInputType.Touch then
                    dragging = true
                    dragStart = input.Position
                    startPos = mainFrame.Position
                    
                    input.Changed:Connect(function()
                        if input.UserInputState == Enum.UserInputState.End then
                            dragging = false
                        end
                    end)
                end
            end)
            
            header.InputChanged:Connect(function(input)
                if (input.UserInputType == Enum.UserInputType.MouseMovement or 
                    input.UserInputType == Enum.UserInputType.Touch) and dragging then
                    local delta = input.Position - dragStart
                    mainFrame.Position = UDim2.new(
                        startPos.X.Scale,
                        startPos.X.Offset + delta.X,
                        startPos.Y.Scale,
                        startPos.Y.Offset + delta.Y
                    )
                end
            end)
            
            -- Minimize functionality
            minButton.MouseButton1Click:Connect(function()
                self:HideMainGUI()
            end)
            
            -- Status updater
            task.spawn(function()
                while screenGui and screenGui.Parent do
                    local status = LagEngine:GetStatus()
                    local text = string.format(
                        "Status: %s\nMode: %s\nObjects: %d\nRuntime: %ds",
                        status.Active and "ACTIVE" or "IDLE",
                        status.Mode or "None",
                        status.Objects,
                        status.Runtime
                    )
                    statusLabel.Text = text
                    task.wait(1)
                end
            end)
            
            return screenGui
        end)
        
        if success then
            self.mainGUI = gui
            self.isVisible = true
            Logger:Add("Main GUI created successfully")
            return gui
        else
            Logger:Add("Failed to create main GUI: " .. tostring(gui), "ERROR")
            return nil
        end
    end,
    
    CreateFloatButton = function(self)
        if self.floatButton and self.floatButton.Parent then
            self.floatButton:Destroy()
        end
        
        local success, btn = pcall(function()
            local floatBtn = Instance.new("TextButton")
            floatBtn.Name = "FloatBtn_" .. GenerateRandomName(6)
            floatBtn.Size = UDim2.new(0, 60, 0, 60)
            floatBtn.Position = UDim2.new(1, -70, 0.5, -30)
            floatBtn.BackgroundColor3 = Color3.fromRGB(70, 120, 200)
            floatBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
            floatBtn.Text = "⚙"
            floatBtn.Font = Enum.Font.GothamBold
            floatBtn.TextSize = 24
            floatBtn.Visible = true
            floatBtn.Parent = CoreGui
            
            local floatCorner = Instance.new("UICorner")
            floatCorner.CornerRadius = UDim.new(1, 0)
            floatCorner.Parent = floatBtn
            
            -- Drag system for float button
            local dragging = false
            local dragStart, startPos
            
            floatBtn.InputBegan:Connect(function(input)
                if input.UserInputType == Enum.UserInputType.MouseButton1 or 
                   input.UserInputType == Enum.UserInputType.Touch then
                    dragging = true
                    dragStart = input.Position
                    startPos = floatBtn.Position
                    
                    input.Changed:Connect(function()
                        if input.UserInputState == Enum.UserInputState.End then
                            dragging = false
                        end
                    end)
                end
            end)
            
            floatBtn.InputChanged:Connect(function(input)
                if (input.UserInputType == Enum.UserInputType.MouseMovement or 
                    input.UserInputType == Enum.UserInputType.Touch) and dragging then
                    local delta = input.Position - dragStart
                    floatBtn.Position = UDim2.new(
                        startPos.X.Scale,
                        startPos.X.Offset + delta.X,
                        startPos.Y.Scale,
                        startPos.Y.Offset + delta.Y
                    )
                end
            end)
            
            floatBtn.MouseButton1Click:Connect(function()
                self:ShowMainGUI()
            end)
            
            return floatBtn
        end)
        
        if success then
            self.floatButton = btn
            Logger:Add("Float button created")
            return btn
        else
            Logger:Add("Failed to create float button: " .. tostring(btn), "ERROR")
            return nil
        end
    end,
    
    ShowMainGUI = function(self)
        if not self.mainGUI or not self.mainGUI.Parent then
            self:CreateMainGUI()
        else
            self.mainGUI.Enabled = true
            self.isVisible = true
        end
        
        if self.floatButton then
            self.floatButton.Visible = false
        end
    end,
    
    HideMainGUI = function(self)
        if self.mainGUI and self.mainGUI.Parent then
            self.mainGUI.Enabled = false
            self.isVisible = false
        end
        
        if not self.floatButton or not self.floatButton.Parent then
            self:CreateFloatButton()
        else
            self.floatButton.Visible = true
        end
    end,
    
    ToggleGUI = function(self)
        if self.isVisible then
            self:HideMainGUI()
        else
            self:ShowMainGUI()
        end
    end,
    
    Initialize = function(self)
        -- Crear float button inicialmente
        self:CreateFloatButton()
        
        -- Crear main GUI pero mantenerla oculta
        self:CreateMainGUI()
        if self.mainGUI then
            self.mainGUI.Enabled = false
            self.isVisible = false
        end
        
        -- Configurar hotkey si no es móvil
        if not isMobile then
            UserInputService.InputBegan:Connect(function(input, processed)
                if not processed and input.KeyCode == Enum.KeyCode.F8 then
                    self:ToggleGUI()
                end
            end)
        end
        
        Logger:Add("UI Controller initialized")
    end
}

-- === INICIALIZACIÓN PRINCIPAL ===
local function Main()
    task.wait(2) -- Esperar a que el juego cargue
    
    -- Inicializar sistemas
    UIController:Initialize()
    RemoteScanner:Scan()
    
    Logger:Add("Resource Manager v4.1 loaded successfully")
    
    -- Limpieza al salir
    Players.PlayerRemoving:Connect(function(player)
        if player == LocalPlayer then
            LagEngine:Stop()
            if UIController.mainGUI then
                UIController.mainGUI:Destroy()
            end
            if UIController.floatButton then
                UIController.floatButton:Destroy()
            end
            Logger:Add("Cleanup completed")
        end
    end)
end

-- Ejecutar con manejo de errores
local success, err = pcall(Main)
if not success then
    warn("Resource Manager Error:", err)
    if isStudio then
        print("Stack Trace:", debug.traceback())
    end
end

-- === EXPORTACIÓN PARA MÓDULO ===
return {
    Start = function(mode)
        return LagEngine:Start(mode)
    end,
    Stop = function()
        LagEngine:Stop()
    end,
    GetStatus = function()
        return LagEngine:GetStatus()
    end,
    ToggleUI = function()
        UIController:ToggleGUI()
    end,
    ShowUI = function()
        UIController:ShowMainGUI()
    end,
    HideUI = function()
        UIController:HideMainGUI()
    end
}